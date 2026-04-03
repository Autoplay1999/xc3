#include <phnt_windows.h>
#include <phnt.h>

#include <stdio.h>
#include <conio.h>
#include <time.h>
#include <psapi.h>
#include <tchar.h>
#include <string>
#include <TlHelp32.h>
#include <iostream>

#include "../xhunter_sdk_lib/xhunterapi.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "Bcrypt.lib")

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
	ULONG       Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG       HandleCount;
	ULONG       PointerCount;
	ULONG       Reserved[10];
} PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

bool SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;

	return TRUE;
}

bool AssignDebugPrivilegeToProcess(HANDLE Process)
{
	bool Rslt = false;
	HANDLE Token = NULL;

	if (OpenProcessToken(Process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		Rslt = SetPrivilege(Token, L"SeDebugPrivilege", true);
		CloseHandle(Token);
	}

	return Rslt;
}

bool AssignDebugPrivilegeToThread(HANDLE Thread)
{
	bool Rslt = false;
	HANDLE Token = NULL;

	if (!OpenThreadToken(Thread, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &Token))
	{
		if (ImpersonateSelf(SecurityImpersonation))
		{
			OpenThreadToken(Thread, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &Token);
		}
	}

	if (Token)
	{
		Rslt = SetPrivilege(Token, L"SeDebugPrivilege", true);
		CloseHandle(Token);
	}

	return Rslt;
}

bool AssignDebugPrivileges()
{
	bool debugPrivProcess = AssignDebugPrivilegeToProcess(GetCurrentProcess());
	bool debugPrivThread = AssignDebugPrivilegeToThread(GetCurrentThread());

	return debugPrivProcess && debugPrivThread;
}

int main()
{
	SetConsoleTitleA("Xigncode SDK");

	XH_HANDLE hClient = XHunter_Connect(NULL, true);

	if (!hClient)
	{
		printf("[-] Failed to get a handle to xhunter1. Is the driver loaded? Client Error = %d\n", XHunter_GetLastError(hClient));
		_getch();
		return -1;
	}

	if (AssignDebugPrivileges() == FALSE)
	{
		wprintf(L"Could not assign debug privileges!\n");
		_getch();
		return -1;
	}

	NTSTATUS st = XHunter_StartHandleHook(hClient);
	if (!NT_SUCCESS(st)) {
		printf("[-] Failed to start handle hook, status: 0x%08X\n", st);
	}
	
	st = XHunter_RegisterReportReader(hClient);
	if (!NT_SUCCESS(st)) {
		printf("[-] Failed to register report reader, status: 0x%08X\n", st);
	}

	while (true)
	{
		system("cls");
		printf("Select Mode\n");
		printf("01. Enable Handle Hook\n");
		printf("02. Disable Handle Hook\n");
		printf("03. Allow PID to Open Process\n");
		printf("04. Add Protected Process\n");
		printf("05. Check Protected Flag From PID\n");
		printf("06. Kernel OpenProcess\n");
		printf("07. Exit\n");

		int iSelect = 0;
		printf("Choose: ");
		if (scanf_s("%d", &iSelect) != 1) {
			// clear input buffer
			int c;
			while ((c = getchar()) != '\n' && c != EOF) {}
			continue;
		}

		switch (iSelect)
		{
			case 1:
			{
				st = XHunter_StartHandleHook(hClient);
				if (NT_SUCCESS(st)) {
					NTSTATUS regRes = XHunter_RegisterReportReader(hClient);
					if (!NT_SUCCESS(regRes)) {
						printf("Failed to register report reader, status: 0x%08X\n", regRes);
					}
					printf("Handle hook started!\n");
				} else {
					printf("Failed to start handle hook, status: 0x%08X\n", st);
				}
				break;
			}
			case 2:
			{
				st = XHunter_StopHandleHook(hClient);
				if (NT_SUCCESS(st)) {
					printf("Handle hook stopped!\n");
				} else {
					printf("Failed to stop handle hook, status: 0x%08X\n", st);
				}
				break;
			}
			case 3:
			{
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				st = XHunter_RegisterPid(hClient, dwPid, PidFlag_Allow);
				if (NT_SUCCESS(st)) {
					printf("Complete!\n");
				} else {
					printf("Failed with status: 0x%08X\n", st);
				}
				break;
			}
			case 4:
			{
				XHunter_RegisterPid(hClient, GetCurrentProcessId(), PidFlag_Protected);
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				st = XHunter_RegisterPid(hClient, dwPid, PidFlag_Protected);
				if (NT_SUCCESS(st)) {
					printf("Complete!\n");
				} else {
					printf("Failed with status: 0x%08X\n", st);
				}
				break;
			}
			case 5:
			{
				DWORD dwPid = 0;
				DWORD flag = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				st = XHunter_GetProtectedProcessFlag(hClient, dwPid, &flag);
				if (NT_SUCCESS(st)) {
					printf("Process Flag: %lu\n", flag);
				} else {
					printf("Failed to get flag, status: 0x%08X\n", st);
				}
				break;
			}
			case 6:
			{
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				
				XHunter_RegisterPid(hClient, GetCurrentProcessId(), PidFlag_Protected | PidFlag_Allow);
				HANDLE hProcess = NULL;
				st = XHunter_OpenProcess(hClient, dwPid, PROCESS_ALL_ACCESS, &hProcess);
				
				if (!NT_SUCCESS(st) || hProcess == INVALID_HANDLE_VALUE || hProcess == NULL) {
					printf("Failed to open process, status: 0x%08X\n", st);
					break;
				}

				PUBLIC_OBJECT_BASIC_INFORMATION objectInformation;
				ULONG objectInformationLength = sizeof(objectInformation);
				CHAR szAccessRight[1000] = { 0 };

				NtQueryObject(hProcess, ObjectBasicInformation, &objectInformation, objectInformationLength, &objectInformationLength);

				if (objectInformation.GrantedAccess >= PROCESS_ALL_ACCESS)
					printf("Handle: %p, ProcessId %lu, Right: PROCESS_ALL_ACCESS\nBreak!!\n", hProcess, GetProcessId(hProcess));
				else
				{
					if (objectInformation.GrantedAccess & PROCESS_TERMINATE)
						lstrcatA(szAccessRight, "PROCESS_TERMINATE\n");
					if (objectInformation.GrantedAccess & PROCESS_CREATE_THREAD)
						lstrcatA(szAccessRight, "PROCESS_CREATE_THREAD\n");
					if (objectInformation.GrantedAccess & PROCESS_SET_SESSIONID)
						lstrcatA(szAccessRight, "PROCESS_SET_SESSIONID\n");
					if (objectInformation.GrantedAccess & PROCESS_VM_OPERATION)
						lstrcatA(szAccessRight, "PROCESS_VM_OPERATION\n");
					if (objectInformation.GrantedAccess & PROCESS_VM_READ)
						lstrcatA(szAccessRight, "PROCESS_VM_READ\n");
					if (objectInformation.GrantedAccess & PROCESS_VM_WRITE)
						lstrcatA(szAccessRight, "PROCESS_VM_WRITE\n");
					if (objectInformation.GrantedAccess & PROCESS_DUP_HANDLE)
						lstrcatA(szAccessRight, "PROCESS_DUP_HANDLE\n");
					if (objectInformation.GrantedAccess & PROCESS_CREATE_PROCESS)
						lstrcatA(szAccessRight, "PROCESS_CREATE_PROCESS\n");
					if (objectInformation.GrantedAccess & PROCESS_SET_QUOTA)
						lstrcatA(szAccessRight, "PROCESS_SET_QUOTA\n");
					if (objectInformation.GrantedAccess & PROCESS_SET_INFORMATION)
						lstrcatA(szAccessRight, "PROCESS_SET_INFORMATION\n");
					if (objectInformation.GrantedAccess & PROCESS_QUERY_INFORMATION)
						lstrcatA(szAccessRight, "PROCESS_QUERY_INFORMATION\n");
					if (objectInformation.GrantedAccess & PROCESS_SUSPEND_RESUME)
						lstrcatA(szAccessRight, "PROCESS_SUSPEND_RESUME\n");
					if (objectInformation.GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION)
						lstrcatA(szAccessRight, "PROCESS_QUERY_LIMITED_INFORMATION\n");
					if (objectInformation.GrantedAccess & PROCESS_SET_LIMITED_INFORMATION)
						lstrcatA(szAccessRight, "PROCESS_SET_LIMITED_INFORMATION\n");

					printf("Handle: %p, Right: %lu\n%s", hProcess, objectInformation.GrantedAccess, szAccessRight);
				}
				
				CloseHandle(hProcess);
				break;
			}
			case 7:
				XHunter_Disconnect(hClient);
				return 0;
			default:
				printf("Invalid option.\n");
				break;
		}
		
		printf("Press any key to continue...\n");
		_getch();
	}

	XHunter_Disconnect(hClient);
	return 0;
}