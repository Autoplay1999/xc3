#include <phnt_windows.h>
#include <phnt.h>

#include <stdio.h>
#include <conio.h>
#include <time.h>
#include <psapi.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <iostream>
#include <iomanip>
#include <filesystem>

#include "../xc3_api/xc3api.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "Bcrypt.lib")

using namespace xc3api;

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

void HexDump(const void* data, size_t size, uint64_t baseAddress)
{
	const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
	for (size_t i = 0; i < size; i += 16) {
		printf("%016llX: ", baseAddress + i);
		
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size)
				printf("%02X ", p[i + j]);
			else
				printf("   ");
			if (j == 7) printf(" ");
		}
		
		printf(" |");
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size) {
				uint8_t c = p[i + j];
				printf("%c", (c >= 32 && c <= 126) ? c : '.');
			}
		}
		printf("|\n");
	}
}

int main()
{
	SetConsoleTitleA("XC3 CLI");

	std::filesystem::path driverPath = "%windir%\\nirvana.sys";
	bool exportDriver = true;

	std::string inputPath;
	std::cout << "Enter driver path [Default: %windir%\\nirvana.sys]: ";
	std::getline(std::cin, inputPath);
	if (!inputPath.empty()) {
		driverPath = inputPath;
	}

	std::string inputExport;
	std::cout << "Export driver? (Y/n) [Default: Y]: ";
	std::getline(std::cin, inputExport);
	if (!inputExport.empty()) {
		if (inputExport[0] == 'n' || inputExport[0] == 'N' || inputExport[0] == '0') {
			exportDriver = false;
		}
	}

	XC3Client client;

	if (!client.Connect(driverPath, exportDriver))
	{
		printf("[-] Failed to get a handle to driver. Is the driver loaded? Client Error = %d\n", client.GetLastError());
		_getch();
		return -1;
	}

	if (AssignDebugPrivileges() == FALSE)
	{
		wprintf(L"Could not assign debug privileges!\n");
		_getch();
		return -1;
	}

	if (auto res = client.StartHandleHook(); !res) {
		printf("[-] Failed to start handle hook, status: 0x%08X\n", res.status());
	}
	
	if (auto res = client.RegisterReportReader(); !res) {
		printf("[-] Failed to register report reader, status: 0x%08X\n", res.status());
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
		printf("07. Read Process Memory (Kernel)\n");
		printf("08. Read Kernel Memory (Direct VA)\n");
		printf("09. Exit\n");

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
				auto res = client.StartHandleHook();
				if (res.is_success()) {
					if (auto regRes = client.RegisterReportReader(); !regRes) {
						printf("Failed to register report reader, status: 0x%08X\n", regRes.status());
					}
					printf("Handle hook started!\n");
				} else {
					printf("Failed to start handle hook, status: 0x%08X\n", res.status());
				}
				break;
			}
			case 2:
			{
				auto res = client.StopHandleHook();
				if (res.is_success()) {
					printf("Handle hook stopped!\n");
				} else {
					printf("Failed to stop handle hook, status: 0x%08X\n", res.status());
				}
				break;
			}
			case 3:
			{
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				auto res = client.RegisterPid(dwPid, PidFlag::FlagAllow);
				if (res.is_success()) {
					printf("Complete!\n");
				} else {
					printf("Failed with status: 0x%08X\n", res.status());
				}
				break;
			}
			case 4:
			{
				client.RegisterPid(GetCurrentProcessId(), PidFlag::FlagProtected);
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				auto res = client.RegisterPid(dwPid, PidFlag::FlagProtected);
				if (res.is_success()) {
					printf("Complete!\n");
				} else {
					printf("Failed with status: 0x%08X\n", res.status());
				}
				break;
			}
			case 5:
			{
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				auto res = client.GetProtectedProcessFlag(dwPid);
				if (res.is_success()) {
					printf("Process Flag: %lu\n", res.value());
				} else {
					printf("Failed to get flag, status: 0x%08X\n", res.status());
				}
				break;
			}
			case 6:
			{
				DWORD dwPid = 0;
				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				
				client.RegisterPid(GetCurrentProcessId(), PidFlag::FlagProtected | PidFlag::FlagAllow);
				auto openRes = client.OpenProcess(dwPid, PROCESS_ALL_ACCESS);
				
				if (!openRes.is_success() || openRes.value() == INVALID_HANDLE_VALUE) {
					printf("Failed to open process, status: 0x%08X\n", openRes.status());
					break;
				}

				HANDLE hProcess = openRes.value();
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
			{
				DWORD dwPid = 0;
				uint64_t targetAddress = 0;
				uint32_t readSize = 64;

				printf("Enter Process ID: "); scanf_s("%lu", &dwPid);
				printf("Enter Address (hex, e.g. 7FF712340000): "); scanf_s("%llx", &targetAddress);
				printf("Enter Size in bytes (default 64): "); scanf_s("%u", &readSize);
				if (readSize == 0 || readSize > 0x100000) readSize = 64;

				client.RegisterPid(GetCurrentProcessId(), PidFlag::FlagProtected | PidFlag::FlagAllow);
				auto openRes = client.OpenProcess(dwPid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
				if (!openRes.is_success() || openRes.value() == INVALID_HANDLE_VALUE) {
					printf("Failed to open process, status: 0x%08X\n", openRes.status());
					break;
				}

				HANDLE hProcess = openRes.value();
				std::vector<uint8_t> buffer(readSize, 0);
				auto readRes = client.ReadProcessMemory(hProcess, targetAddress, buffer.data(), readSize);
				if (readRes.is_success()) {
					printf("[+] Successfully read %u bytes:\n\n", readSize);
					HexDump(buffer.data(), readSize, targetAddress);
				} else {
					printf("[-] ReadProcessMemory failed, status: 0x%08X\n", readRes.status());
				}

				CloseHandle(hProcess);
				break;
			}
			case 8:
			{
				uint64_t kernelVa = 0;
				uint32_t readSize = 64;

				printf("Enter Kernel VA (hex, e.g. FFFFF80012345678): "); scanf_s("%llx", &kernelVa);
				printf("Enter Size in bytes (default 64): "); scanf_s("%u", &readSize);
				if (readSize == 0 || readSize > 0x100000) readSize = 64;

				std::vector<uint8_t> buffer(readSize, 0);
				auto readRes = client.ReadKernelMemory(kernelVa, buffer.data(), readSize);
				if (readRes.is_success()) {
					printf("[+] Successfully read %u kernel bytes:\n\n", readSize);
					HexDump(buffer.data(), readSize, kernelVa);
				} else {
					printf("[-] ReadKernelMemory failed, status: 0x%08X\n", readRes.status());
				}
				break;
			}
			case 9:
				return 0;
			default:
				printf("Invalid option.\n");
				break;
		}
		
		printf("Press any key to continue...\n");
		_getch();
	}

	return 0;
}
