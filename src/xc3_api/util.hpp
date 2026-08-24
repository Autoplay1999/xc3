#define NT_REG_PREP             "\\Registry\\Machine\\"
#define DRIVER_REGKEY           "System\\CurrentControlSet\\Services\\"

#include <windows.h>
#include <bcrypt.h>
#include <span>
#include <string>
#include <vector>
#include <format>
#include <std_format_ext.h>
#include <scope_guard.hpp>
#include <xorstr.hpp>
#include <VMProtectSDK.h>

#include "error.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace util {
    namespace crypto {
        inline std::string sha512_hex(std::span<const std::byte> data) noexcept {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            std::string hex_out;

            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, 0) < 0) {
                return {};
            }
            auto alg_guard = scope_guard::make_scope_exit([&] { BCryptCloseAlgorithmProvider(hAlg, 0); });

            DWORD hashObjSize = 0, cbData = 0, hashLen = 0;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&hashObjSize), sizeof(DWORD), &cbData, 0) < 0 ||
                BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&hashLen), sizeof(DWORD), &cbData, 0) < 0) {
                return {};
            }

            std::vector<uint8_t> hashObj(hashObjSize);
            std::vector<uint8_t> hashBuf(hashLen);

            if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) >= 0) {
                auto hash_guard = scope_guard::make_scope_exit([&] { BCryptDestroyHash(hHash); });
                if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())), static_cast<ULONG>(data.size()), 0) >= 0 &&
                    BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0) >= 0) {
                    constexpr char hexDigits[] = "0123456789abcdef";
                    hex_out.reserve(hashLen * 2);
                    for (uint8_t b : hashBuf) {
                        hex_out.push_back(hexDigits[(b >> 4) & 0xF]);
                        hex_out.push_back(hexDigits[b & 0xF]);
                    }
                }
            }

            return hex_out;
        }
    }

    // Service Management Utilities using RAII scope_guard
    inline bool is_service_running(const std::wstring& name) noexcept {
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;
        auto scm_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(scManager); });

        SC_HANDLE service = OpenServiceW(scManager, name.c_str(), SERVICE_QUERY_STATUS);
        if (!service) return false;
        auto svc_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(service); });

        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
            return (status.dwCurrentState == SERVICE_RUNNING);
        }

        return false;
    }

    inline bool service_exists(const std::wstring& name) noexcept {
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;
        auto scm_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(scManager); });

        SC_HANDLE service = OpenServiceW(scManager, name.c_str(), SERVICE_QUERY_STATUS);
        if (!service) return false;
        CloseServiceHandle(service);
        return true;
    }

    inline bool create_service_entry(const std::wstring& name, const std::wstring& displayName, const std::wstring& binaryPath) noexcept {
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scManager) return false;
        auto scm_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(scManager); });

        SC_HANDLE service = CreateServiceW(
            scManager,
            name.c_str(),
            displayName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binaryPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!service) return false;
        CloseServiceHandle(service);
        return true;
    }

    inline bool start_service_entry(const std::wstring& name) noexcept {
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;
        auto scm_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(scManager); });

        SC_HANDLE service = OpenServiceW(scManager, name.c_str(), SERVICE_START);
        if (!service) return false;
        auto svc_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(service); });

        return StartServiceW(service, 0, nullptr) != FALSE;
    }

    inline bool stop_service_entry(const std::wstring& name) noexcept {
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;
        auto scm_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(scManager); });

        SC_HANDLE service = OpenServiceW(scManager, name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!service) return false;
        auto svc_guard = scope_guard::make_scope_exit([&] { CloseServiceHandle(service); });

        SERVICE_STATUS status;
        return ControlService(service, SERVICE_CONTROL_STOP, &status) != FALSE;
    }

    typedef struct _OBJSCANPARAM {
        PCWSTR Buffer;
        ULONG BufferSize;
    } OBJSCANPARAM, * POBJSCANPARAM;

    typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(
        _In_ POBJECT_DIRECTORY_INFORMATION Entry,
        _In_opt_ PVOID CallbackParam);

    inline NTSTATUS __stdcall ntsupDetectObjectCallback(_In_ POBJECT_DIRECTORY_INFORMATION Entry, _In_ PVOID CallbackParam) {
        POBJSCANPARAM Param = static_cast<POBJSCANPARAM>(CallbackParam);

        if (Entry == NULL) {
            return STATUS_INVALID_PARAMETER_1;
        }

        if (CallbackParam == NULL) {
            return STATUS_INVALID_PARAMETER_2;
        }

        if (Param->Buffer == NULL || Param->BufferSize == 0) {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }

        if (Entry->Name.Buffer) {
            if (_wcsicmp(Entry->Name.Buffer, Param->Buffer) == 0) {
                return STATUS_SUCCESS;
            }
        }
        return STATUS_UNSUCCESSFUL;
    }

    inline NTSTATUS __stdcall ntsupEnumSystemObjects(_In_opt_ LPCWSTR pwszRootDirectory, _In_opt_ HANDLE hRootDirectory, _In_ PENUMOBJECTSCALLBACK CallbackProc, _In_opt_ PVOID CallbackParam) {
        ULONG               ctx, rlen;
        HANDLE              hDirectory = NULL;
        NTSTATUS            status;
        NTSTATUS            CallbackStatus;
        OBJECT_ATTRIBUTES   attr;
        UNICODE_STRING      sname;

        POBJECT_DIRECTORY_INFORMATION    objinf;

        if (CallbackProc == NULL) {
            return STATUS_INVALID_PARAMETER_4;
        }

        status = STATUS_UNSUCCESSFUL;

        if (pwszRootDirectory != NULL) {
            RtlSecureZeroMemory(&sname, sizeof(sname));
            RtlInitUnicodeString(&sname, pwszRootDirectory);
            InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        } else {
            if (hRootDirectory == NULL) {
                return STATUS_INVALID_PARAMETER_2;
            }
            hDirectory = hRootDirectory;
        }

        auto dir_guard = scope_guard::make_scope_exit([&] {
            if (hDirectory != NULL) {
                NtClose(hDirectory);
            }
        });

        ctx = 0;
        do {
            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;

            objinf = static_cast<POBJECT_DIRECTORY_INFORMATION>(malloc(rlen));
            if (objinf == NULL)
                break;

            auto obj_guard = scope_guard::make_scope_exit([&] { free(objinf); });

            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);
            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }
        } while (TRUE);

        return status;
    }

    inline BOOL supxDeleteKeyRecursive(_In_ HKEY hKeyRoot, _In_ LPCWSTR lpSubKey) {
        LPWSTR lpEnd;
        LONG lResult;
        DWORD dwSize;
        WCHAR szName[MAX_PATH + 1];
        HKEY hKey;
        FILETIME ftWrite;

        lResult = RegDeleteKeyW(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS)
            return TRUE;

        lResult = RegOpenKeyExW(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
        if (lResult != ERROR_SUCCESS) {
            return (lResult == ERROR_FILE_NOT_FOUND);
        }

        auto key_guard = scope_guard::make_scope_exit([&] { RegCloseKey(hKey); });

        lpEnd = const_cast<LPWSTR>(&lpSubKey[wcslen(lpSubKey)]);
        if (*(lpEnd - 1) != L'\\') {
            *lpEnd = L'\\';
            lpEnd++;
            *lpEnd = L'\0';
        }

        dwSize = MAX_PATH;
        lResult = RegEnumKeyExW(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);

        if (lResult == ERROR_SUCCESS) {
            do {
                wcscpy_s(lpEnd, MAX_PATH, szName);
                if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                    break;

                dwSize = MAX_PATH;
                lResult = RegEnumKeyExW(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);
            } while (lResult == ERROR_SUCCESS);
        }

        lpEnd--;
        *lpEnd = L'\0';

        key_guard.dismiss();
        RegCloseKey(hKey);

        return RegDeleteKeyW(hKeyRoot, lpSubKey) == ERROR_SUCCESS;
    }

    inline bool create_service_registry(std::wstring_view serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("whsevsONw6zM8lH1pdMSZCyrRkRmm9LMUGkZ8VlbkXwQAYkXdV09jaqd4UY5R9jt");
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD dwData, dwResult;
        HKEY keyHandle = NULL;
        UNICODE_STRING driverImagePath;

        RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

        if (!driverPath.empty()) {
            if (!RtlDosPathNameToNtPathName_U(driverPath.data(), &driverImagePath, NULL, NULL)) {
                return false;
            }
        }

        auto path_guard = scope_guard::make_scope_exit([&] {
            if (!driverPath.empty() && driverImagePath.Buffer) {
                RtlFreeUnicodeString(&driverImagePath);
            }
        });

        if (ERROR_SUCCESS != RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                            std::format_(XSW(DRIVER_REGKEY "{}"), serviceName).c_str(),
                                            0,
                                            NULL,
                                            REG_OPTION_NON_VOLATILE,
                                            KEY_ALL_ACCESS,
                                            NULL,
                                            &keyHandle,
                                            NULL)) {
            VMP_END();
            return false;
        }

        auto reg_guard = scope_guard::make_scope_exit([&] { RegCloseKey(keyHandle); });

        dwResult = ERROR_SUCCESS;
        do {
            dwData = SERVICE_ERROR_NORMAL;
            dwResult = RegSetValueExW(keyHandle, XSW("ErrorControl"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwData), sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            dwData = SERVICE_KERNEL_DRIVER;
            dwResult = RegSetValueExW(keyHandle, XSW("Type"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwData), sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            dwData = SERVICE_DEMAND_START;
            dwResult = RegSetValueExW(keyHandle, XSW("Start"), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwData), sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            if (!driverPath.empty()) {
                dwResult = RegSetValueExW(keyHandle, XSW("ImagePath"), 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(driverImagePath.Buffer), static_cast<DWORD>(driverImagePath.Length + sizeof(UNICODE_NULL)));
            }
        } while (FALSE);

        status = (dwResult == ERROR_SUCCESS) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
        VMP_END();
        return NT_SUCCESS(status);
    }

    inline xc3::Result<void> load_driver_nt(std::wstring_view serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("ljSjtwzkVR3ahHaDNSs73kZefoCYzKgI42YcWdq3JlGmbxi6nZeHrs3YpetI2lYg");
        if (!create_service_registry(serviceName, driverPath)) {
            X_FAIL_MSG(XSA("Failed to create driver entry in registry"));
        }

        std::wstring wsDriverServiceName = std::format_(XSW(NT_REG_PREP DRIVER_REGKEY "{}"), serviceName);

        UNICODE_STRING usDriverServiceName;
        usDriverServiceName.Buffer = const_cast<PWSTR>(wsDriverServiceName.data());
        usDriverServiceName.Length = static_cast<USHORT>(wsDriverServiceName.size() * sizeof(wchar_t));
        usDriverServiceName.MaximumLength = static_cast<USHORT>(wsDriverServiceName.size() * sizeof(wchar_t));

        NTSTATUS status = NtLoadDriver(&usDriverServiceName);
        if (!NT_SUCCESS(status)) {
            X_FAIL(status, XSA("NtLoadDriver failed"));
        }

        VMP_END();
        return {};
    }

    inline xc3::Result<void> unload_driver_nt(const std::wstring& serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("6cO06W8iBW0HPbLCKX5qd9wkqDsxh24zyJ8dxLz5pqRb6KcfEO0ctgxHOvIfLSTe");
        if (!create_service_registry(serviceName, driverPath)) {
            X_FAIL_MSG(XSA("Failed to create driver registry keys for unload"));
        }

        std::wstring wsDriverServiceName = std::format_(XSW(NT_REG_PREP DRIVER_REGKEY "{}"), serviceName);

        UNICODE_STRING usDriverServiceName;
        usDriverServiceName.Buffer = const_cast<PWSTR>(wsDriverServiceName.data());
        usDriverServiceName.Length = static_cast<USHORT>(wsDriverServiceName.size() * sizeof(wchar_t));
        usDriverServiceName.MaximumLength = static_cast<USHORT>(wsDriverServiceName.size() * sizeof(wchar_t));

        NTSTATUS status = NtUnloadDriver(&usDriverServiceName);
        if (NT_SUCCESS(status)) {
            supxDeleteKeyRecursive(HKEY_LOCAL_MACHINE, wsDriverServiceName.substr(0, 18).c_str());
        } else {
            X_FAIL(status, XSA("NtUnloadDriver failed"));
        }

        VMP_END();
        return {};
    }

    inline bool is_driver_loaded(std::wstring ObjectName) {
        OBJSCANPARAM Param;
        Param.Buffer = ObjectName.c_str();
        Param.BufferSize = static_cast<ULONG>(ObjectName.size());

        return NT_SUCCESS(ntsupEnumSystemObjects(XSW("\\Device"), NULL, ntsupDetectObjectCallback, &Param));
    }
}
