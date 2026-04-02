#define NT_REG_PREP             "\\Registry\\Machine\\"
#define DRIVER_REGKEY           "System\\CurrentControlSet\\Services\\"

#ifdef __XHUNTER_VERBOSE
#define XHUNTER_TRACE(fmt, ...) printf("[XHunter] " fmt, __VA_ARGS__);
#else
#define XHUNTER_TRACE(...)
#endif

namespace util {
    typedef struct _OBJSCANPARAM {
        PCWSTR Buffer;
        ULONG BufferSize;
    } OBJSCANPARAM, * POBJSCANPARAM;

    typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(
        _In_ POBJECT_DIRECTORY_INFORMATION Entry,
        _In_opt_ PVOID CallbackParam);

    NTSTATUS __stdcall ntsupDetectObjectCallback(_In_ POBJECT_DIRECTORY_INFORMATION Entry,_In_ PVOID CallbackParam) {
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

    NTSTATUS __stdcall ntsupEnumSystemObjects(_In_opt_ LPCWSTR pwszRootDirectory,_In_opt_ HANDLE hRootDirectory,_In_ PENUMOBJECTSCALLBACK CallbackProc, _In_opt_ PVOID CallbackParam) {
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

    BOOL supxDeleteKeyRecursive(_In_ HKEY hKeyRoot, _In_ LPCWSTR lpSubKey) {
        LPWSTR lpEnd;
        LONG lResult;
        DWORD dwSize;
        WCHAR szName[MAX_PATH + 1];
        HKEY hKey;
        FILETIME ftWrite;

        //
        // Attempt to delete key as is.
        //
        lResult = RegDeleteKey(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS)
            return TRUE;

        //
        // Try to open key to check if it exist.
        //
        lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
        if (lResult != ERROR_SUCCESS) {
            if (lResult == ERROR_FILE_NOT_FOUND)
                return TRUE;
            else
                return FALSE;
        }

        //
        // Add slash to the key path if not present.
        //
        lpEnd = (LPWSTR)&lpSubKey[wcslen(lpSubKey)];
        if (*(lpEnd - 1) != TEXT('\\')) {
            *lpEnd = TEXT('\\');
            lpEnd++;
            *lpEnd = TEXT('\0');
        }

        //
        // Enumerate subkeys and call this func for each.
        //
        dwSize = MAX_PATH;
        lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                                NULL, NULL, &ftWrite);

        if (lResult == ERROR_SUCCESS) {

            do {

                wcscpy(lpEnd, szName);

                if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                    break;

                dwSize = MAX_PATH;

                lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                                        NULL, NULL, &ftWrite);

            } while (lResult == ERROR_SUCCESS);
        }

        lpEnd--;
        *lpEnd = TEXT('\0');

        RegCloseKey(hKey);

        //
        // Delete current key, all it subkeys should be already removed.
        //
        lResult = RegDeleteKey(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS)
            return TRUE;

        return FALSE;
    }

	bool create_driver_entry(std::wstring_view serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("whsevsONw6zM8lH1pdMSZCyrRkRmm9LMUGkZ8VlbkXwQAYkXdV09jaqd4UY5R9jt");
#if 0
		SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

		if (!scManager)
			return false;

		SC_HANDLE service = CreateService(
			scManager,
			serviceName.c_str(),
			L"",
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
			nullptr, nullptr, nullptr, nullptr, nullptr);

		if (!service) {
			CloseServiceHandle(scManager);
			return false;
		}

		CloseServiceHandle(service);
		CloseServiceHandle(scManager);
#else
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD dwData, dwResult;
        HKEY keyHandle = NULL;
        UNICODE_STRING driverImagePath;

        RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

        if (!driverPath.empty()) {
            if (!RtlDosPathNameToNtPathName_U(driverPath.data(),
                                              &driverImagePath,
                                              NULL,
                                              NULL)) {
                return STATUS_INVALID_PARAMETER_2;
            }
        }

        if (ERROR_SUCCESS != RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                            std::format_(XSW(DRIVER_REGKEY "{}"), serviceName).c_str(),
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
            dwResult = RegSetValueExW(keyHandle,
                                     XSW("ErrorControl"),
                                     0,
                                     REG_DWORD,
                                     (BYTE*)&dwData,
                                     sizeof(dwData));
            if (dwResult != ERROR_SUCCESS)
                break;

            dwData = SERVICE_KERNEL_DRIVER;
            dwResult = RegSetValueExW(keyHandle,
                                     XSW("Type"),
                                     0,
                                     REG_DWORD,
                                     (BYTE*)&dwData,
                                     sizeof(dwData));
            if (dwResult != ERROR_SUCCESS)
                break;

            dwData = SERVICE_DEMAND_START;
            dwResult = RegSetValueExW(keyHandle,
                                     XSW("Start"),
                                     0,
                                     REG_DWORD,
                                     (BYTE*)&dwData,
                                     sizeof(dwData));

            if (dwResult != ERROR_SUCCESS)
                break;

            if (!driverPath.empty()) {
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
        if (!driverPath.empty()) {
            if (driverImagePath.Buffer) {
                RtlFreeUnicodeString(&driverImagePath);
            }
        }
#endif
        VMP_END();
		return true;
	}
    
    bool load_driver(std::wstring_view serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("ljSjtwzkVR3ahHaDNSs73kZefoCYzKgI42YcWdq3JlGmbxi6nZeHrs3YpetI2lYg");
#if 0
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

        if (!scManager)
            return false;

        SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_START);

        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        if (!StartService(service, 0, nullptr)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            return false;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
#else
        if (!create_driver_entry(serviceName, driverPath)) {
            XHUNTER_TRACE("Failed to create driver entry");
            return false;
        }

        std::wstring wsDriverServiceName = std::format_(XSW(NT_REG_PREP  DRIVER_REGKEY "{}"), serviceName).c_str();

        UNICODE_STRING usDriverServiceName;
        usDriverServiceName.Buffer = wsDriverServiceName.data();
        usDriverServiceName.Length = wsDriverServiceName.size() * sizeof(wchar_t);
        usDriverServiceName.MaximumLength = wsDriverServiceName.size() * sizeof(wchar_t);

        if (!NT_SUCCESS(NtLoadDriver(&usDriverServiceName)))
            return false;

#endif
        VMP_END();
		return true;
	}

	bool unload_driver(const std::wstring& serviceName, std::wstring_view driverPath) {
        VMP_BEGIN_MUTATION("6cO06W8iBW0HPbLCKX5qd9wkqDsxh24zyJ8dxLz5pqRb6KcfEO0ctgxHOvIfLSTe");
#if 0
        SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

        if (!scManager)
            return false;

        SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);

        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        SERVICE_STATUS status;

        if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            return false;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
#else
        if (!create_driver_entry(serviceName, driverPath)) {
            XHUNTER_TRACE("Failed to create driver entry");
            return false;
        }

        std::wstring wsDriverServiceName = std::format_(XSW(NT_REG_PREP  DRIVER_REGKEY "{}"), serviceName).c_str();

        UNICODE_STRING usDriverServiceName;
        usDriverServiceName.Buffer = wsDriverServiceName.data();
        usDriverServiceName.Length = wsDriverServiceName.size() * sizeof(wchar_t);
        usDriverServiceName.MaximumLength = wsDriverServiceName.size() * sizeof(wchar_t);

        if (NT_SUCCESS(NtUnloadDriver(&usDriverServiceName))) {
            supxDeleteKeyRecursive(HKEY_LOCAL_MACHINE, wsDriverServiceName.substr(0, 18).c_str());
        }
#endif
        VMP_END();
		return true;
	}

	bool drvier_is_already_loaded(std::wstring ObjectName) {
        OBJSCANPARAM Param;

        Param.Buffer = ObjectName.c_str();
        Param.BufferSize = (ULONG)ObjectName.size();

        return NT_SUCCESS(ntsupEnumSystemObjects(XSW("\\Device"), NULL, ntsupDetectObjectCallback, &Param));
	}
}