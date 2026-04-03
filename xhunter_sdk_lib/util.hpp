#pragma once
#ifndef UTIL_HPP
#define UTIL_HPP

#include <phnt_windows.h>
#include <phnt.h>
#include <strsafe.h>

#define NT_REG_PREP             L"\\Registry\\Machine\\"
#define DRIVER_REGKEY           L"System\\CurrentControlSet\\Services\\"

namespace util {
    // Service Management Utilities
    inline bool is_service_running(const wchar_t* name) noexcept {
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceW(scManager, name, SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        bool running = false;

        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            running = (status.dwCurrentState == SERVICE_RUNNING);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);

        return running;
    }

    inline bool service_exists(const wchar_t* name) noexcept {
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceW(scManager, name, SERVICE_QUERY_STATUS);
        bool exists = service != nullptr;

        if (service) CloseServiceHandle(service);
        CloseServiceHandle(scManager);

        return exists;
    }

    inline bool create_service_entry(const wchar_t* name, const wchar_t* displayName, const wchar_t* binaryPath) noexcept {
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scManager) return false;

        SC_HANDLE service = CreateServiceW(
            scManager,
            name,
            displayName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binaryPath,
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return true;
    }

    inline bool start_service_entry(const wchar_t* name) noexcept {
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceW(scManager, name, SERVICE_START);
        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        bool success = StartServiceW(service, 0, nullptr);

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return success;
    }

    inline bool stop_service_entry(const wchar_t* name) noexcept {
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceW(scManager, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        SERVICE_STATUS status;
        bool success = ControlService(service, SERVICE_CONTROL_STOP, &status);

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return success;
    }

    typedef struct _OBJSCANPARAM {
        PCWSTR Buffer;
        ULONG BufferSize;
    } OBJSCANPARAM, * POBJSCANPARAM;

    typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(
        _In_ POBJECT_DIRECTORY_INFORMATION Entry,
        _In_opt_ PVOID CallbackParam);

    inline NTSTATUS __stdcall ntsupDetectObjectCallback(_In_ POBJECT_DIRECTORY_INFORMATION Entry,_In_ PVOID CallbackParam) {
        POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

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

    inline NTSTATUS __stdcall ntsupEnumSystemObjects(_In_opt_ LPCWSTR pwszRootDirectory,_In_opt_ HANDLE hRootDirectory,_In_ PENUMOBJECTSCALLBACK CallbackProc, _In_opt_ PVOID CallbackParam) {
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

        // We can use root directory.
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

        // Enumerate objects in directory.
        ctx = 0;
        do {

            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;

            objinf = (POBJECT_DIRECTORY_INFORMATION)malloc(rlen);

            if (objinf == NULL)
                break;

            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                free(objinf);
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);

            free(objinf);

            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }

        } while (TRUE);

        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }

        return status;
    }

    inline BOOL supxDeleteKeyRecursive(_In_ HKEY hKeyRoot, _In_ LPCWSTR lpSubKey) {
        LPWSTR lpEnd;
        LONG lResult;
        DWORD dwSize;
        WCHAR szName[MAX_PATH + 1];
        HKEY hKey;
        FILETIME ftWrite;

        // Attempt to delete key as is.
        lResult = RegDeleteKeyW(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS)
            return TRUE;

        // Try to open key to check if it exist.
        lResult = RegOpenKeyExW(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
        if (lResult != ERROR_SUCCESS) {
            if (lResult == ERROR_FILE_NOT_FOUND)
                return TRUE;
            else
                return FALSE;
        }

        // Add slash to the key path if not present.
        lpEnd = (LPWSTR)&lpSubKey[wcslen(lpSubKey)];
        if (*(lpEnd - 1) != L'\\') {
            *lpEnd = L'\\';
            lpEnd++;
            *lpEnd = L'\0';
        }

        // Enumerate subkeys and call this func for each.
        dwSize = MAX_PATH;
        lResult = RegEnumKeyExW(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);

        if (lResult == ERROR_SUCCESS) {
            do {
                wcscpy_s(lpEnd, MAX_PATH - (lpEnd - lpSubKey), szName);

                if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                    break;

                dwSize = MAX_PATH;
                lResult = RegEnumKeyExW(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);
            } while (lResult == ERROR_SUCCESS);
        }

        lpEnd--;
        *lpEnd = L'\0';

        RegCloseKey(hKey);

        // Delete current key, all it subkeys should be already removed.
        lResult = RegDeleteKeyW(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS)
            return TRUE;

        return FALSE;
    }

	inline bool create_service_registry(const wchar_t* serviceName, const wchar_t* driverPath) {
        VMP_BEGIN_MUTATION("whsevsONw6zM8lH1pdMSZCyrRkRmm9LMUGkZ8VlbkXwQAYkXdV09jaqd4UY5R9jt");
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD dwData, dwResult;
        HKEY keyHandle = NULL;
        UNICODE_STRING driverImagePath;

        RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

        if (driverPath && driverPath[0] != L'\0') {
            if (!RtlDosPathNameToNtPathName_U(driverPath,
                                              &driverImagePath,
                                              NULL,
                                              NULL)) {
                return false;
            }
        }

        wchar_t regPath[MAX_PATH];
        StringCbPrintfW(regPath, sizeof(regPath), L"%s%s", DRIVER_REGKEY, serviceName);

        if (ERROR_SUCCESS != RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                            regPath,
                                            0,
                                            NULL,
                                            REG_OPTION_NON_VOLATILE,
                                            KEY_ALL_ACCESS,
                                            NULL,
                                            &keyHandle,
                                            NULL)) {
            status = STATUS_ACCESS_DENIED;
            goto Cleanup;
        }

        dwResult = ERROR_SUCCESS;

        do {
            dwData = SERVICE_ERROR_NORMAL;
            dwResult = RegSetValueExW(keyHandle, XSW("ErrorControl"), 0, REG_DWORD, (BYTE*)&dwData, sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            dwData = SERVICE_KERNEL_DRIVER;
            dwResult = RegSetValueExW(keyHandle, XSW("Type"), 0, REG_DWORD, (BYTE*)&dwData, sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            dwData = SERVICE_DEMAND_START;
            dwResult = RegSetValueExW(keyHandle, XSW("Start"), 0, REG_DWORD, (BYTE*)&dwData, sizeof(dwData));
            if (dwResult != ERROR_SUCCESS) break;

            if (driverPath && driverPath[0] != L'\0') {
                dwResult = RegSetValueExW(keyHandle,
                                         XSW("ImagePath"),
                                         0,
                                         REG_EXPAND_SZ,
                                         (BYTE*)driverImagePath.Buffer,
                                         (DWORD)driverImagePath.Length + sizeof(UNICODE_NULL));
            }
        } while (FALSE);

        RegCloseKey(keyHandle);

        if (dwResult != ERROR_SUCCESS) {
            status = STATUS_ACCESS_DENIED;
        } else {
            status = STATUS_SUCCESS;
        }

Cleanup:
        if (driverPath && driverPath[0] != L'\0') {
            if (driverImagePath.Buffer) {
                RtlFreeUnicodeString(&driverImagePath);
            }
        }
        VMP_END();
		return NT_SUCCESS(status);
	}
    
	inline NTSTATUS load_driver_nt(const wchar_t* serviceName, const wchar_t* driverPath) {
        VMP_BEGIN_MUTATION("ljSjtwzkVR3ahHaDNSs73kZefoCYzKgI42YcWdq3JlGmbxi6nZeHrs3YpetI2lYg");
        if (!create_service_registry(serviceName, driverPath)) {
            return STATUS_ACCESS_DENIED;
        }

        wchar_t wsDriverServiceName[MAX_PATH];
        StringCbPrintfW(wsDriverServiceName, sizeof(wsDriverServiceName), L"%s%s%s", NT_REG_PREP, DRIVER_REGKEY, serviceName);

        UNICODE_STRING usDriverServiceName;
        RtlInitUnicodeString(&usDriverServiceName, wsDriverServiceName);

        NTSTATUS status = NtLoadDriver(&usDriverServiceName);
        
        VMP_END();
		return status;
	}

	inline NTSTATUS unload_driver_nt(const wchar_t* serviceName, const wchar_t* driverPath) {
        VMP_BEGIN_MUTATION("6cO06W8iBW0HPbLCKX5qd9wkqDsxh24zyJ8dxLz5pqRb6KcfEO0ctgxHOvIfLSTe");
        if (!create_service_registry(serviceName, driverPath)) {
            return STATUS_ACCESS_DENIED;
        }

        wchar_t wsDriverServiceName[MAX_PATH];
        StringCbPrintfW(wsDriverServiceName, sizeof(wsDriverServiceName), L"%s%s%s", NT_REG_PREP, DRIVER_REGKEY, serviceName);

        UNICODE_STRING usDriverServiceName;
        RtlInitUnicodeString(&usDriverServiceName, wsDriverServiceName);

        NTSTATUS status = NtUnloadDriver(&usDriverServiceName);
        if (NT_SUCCESS(status)) {
            wchar_t baseRegPath[MAX_PATH];
            StringCbPrintfW(baseRegPath, sizeof(baseRegPath), L"%s%s", DRIVER_REGKEY, serviceName);
            supxDeleteKeyRecursive(HKEY_LOCAL_MACHINE, baseRegPath);
        }

        VMP_END();
		return status;
	}

	inline bool is_driver_loaded(const wchar_t* objectName) {
        OBJSCANPARAM Param;
        Param.Buffer = objectName;
        Param.BufferSize = (ULONG)(wcslen(objectName) * sizeof(wchar_t));

        return NT_SUCCESS(ntsupEnumSystemObjects(XSW("\\Device"), NULL, ntsupDetectObjectCallback, &Param));
	}
}

#endif