#include <phnt_windows.h>
#include <phnt.h>

#include <stdio.h>
#include <conio.h>
#include <time.h>
#include <psapi.h>
#include <tchar.h>
#include <string>
#include <TlHelp32.h>

#include "../xhunter_sdk_lib/xhunterapi.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "Bcrypt.lib")

HANDLE hDriver = 0;

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

	// Enable the privilege or disable all privileges.
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

	//system("net start xhunter1");
	hDriver = xhunterapi::get_xhunter1_handle();

	if (AssignDebugPrivileges() == FALSE)
	{
		wprintf(L"Could not assign debug privileges!\n");
		_getch();
		return -1;
	}

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to get a handle to xhunter1. Is the driver loaded? GetLastError() = %lu\n", GetLastError());
		_getch();
		return -1;
	}

	xhunterapi::StartHandleHook(hDriver);
	xhunterapi::XRegisterReportReader(hDriver);
xhuntersdk:
	unsigned int i = 0;
	HANDLE hProcess = 0;
	DWORD dwPid, dwFlag;
	PUBLIC_OBJECT_BASIC_INFORMATION objectInformation;
	ULONG objectInformationLength = sizeof(objectInformation);
	CHAR szAccessRight[1000] = { 0 };

	system("cls");
	printf("Select Mode\n");
	printf("01. Enable Handle Hook\n");
	printf("02. Disable Handle Hook\n");
	printf("03. Allow PID to Open Process\n");
	printf("04. Add Protected Process\n");
	printf("05. Check Protected Flag From PID\n");
	printf("06. Kernel OpenProcess\n");

	int iSelect = 0;
	printf("Choose: "); scanf_s("%d", &iSelect);
	switch (iSelect)
	{
		case 1:
		{
			xhunterapi::StartHandleHook(hDriver);
			xhunterapi::XRegisterReportReader(hDriver);
			printf("Handle hook started!\n");
		}
		break;
		case 2:
		{
			xhunterapi::StopHandleHook(hDriver);
			printf("Handle hook stopped!\n");
		}
		break;
		case 3:
		{
			printf("Enter Process ID: "); scanf_s("%d", &dwPid);
			xhunterapi::RegisterPid(hDriver, dwPid, ZXTF_PID_ALLOW);
			printf("Complete!");
		}
		break;
		case 4:
		{
			xhunterapi::RegisterPid(hDriver, GetCurrentProcessId(), ZXTF_PID_PROTECTED);
			printf("Enter Process ID: "); scanf_s("%d", &dwPid);
			xhunterapi::RegisterPid(hDriver, dwPid, ZXTF_PID_PROTECTED);
			printf("Complete!");
		}
		break;
		case 5:
		{
			printf("Enter Process ID: "); scanf_s("%d", &dwPid);
			dwFlag = xhunterapi::GetProtectedProcessFlag(hDriver, dwPid);
			printf("Process Flag: %d\n", dwFlag);
		}
		break;
		case 6:
		{
			printf("Enter Process ID: "); scanf_s("%d", &dwPid);		
			xhunterapi::RegisterPid(hDriver, GetCurrentProcessId(), ZXTF_PID_PROTECTED | ZXTF_PID_ALLOW);
			hProcess = xhunterapi::XOpenProcess(hDriver, dwPid, PROCESS_ALL_ACCESS);		
			NtQueryObject(hProcess, ObjectBasicInformation, &objectInformation, objectInformationLength, &objectInformationLength);

			if (objectInformation.GrantedAccess >= PROCESS_ALL_ACCESS)
				printf("Handle: %p, ProcessId %u, Right: PROCESS_ALL_ACCESS\nBreak!!\n", hProcess, GetProcessId(hProcess));
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

				printf("Handle: %p, Right: %d\n%s", hProcess, objectInformation.GrantedAccess, szAccessRight);
			}
			_getch();
			CloseHandle(hProcess);
		}
		break;
		default:
			goto xhuntersdk;
			break;
	}
	_getch();
	goto xhuntersdk;
	return 0;
}