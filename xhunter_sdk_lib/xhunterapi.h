#pragma once
#pragma comment(lib, "ntdll.lib")

#ifndef XHUNTER_API_H
#define XHUNTER_API_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum _PidFlag {
		PidFlag_Allow = 1,
		PidFlag_Deny = 2,
		PidFlag_Unprotect = 4,
		PidFlag_Protected = 8,
		PidFlag_ReportAuthenticated = 0x40000000,
		PidFlag_ReportProcess = 0x80000000
	} PidFlag;

	typedef enum _Opcode {
		Opcode_MapPid = 775,
		Opcode_RegisterReportReader = 777,
		Opcode_UnmapPid = 779,
		Opcode_SetHookState = 782,
		Opcode_OpenProcess = 785,
		Opcode_GetProtectFlag = 797
	} Opcode;

#pragma pack(push, 1)
	struct ObjectHandleInfo
	{
		BOOLEAN Inherit;
		BOOLEAN ProtectFromClose;
	};

	struct xhunter1_common_hdr
	{
		uint32_t pkt_size; //0
		uint32_t pkt_magic; //4
		uint32_t pkt_req_id; //8
	};

	struct xhunter1_req_hdr
	{
		struct xhunter1_common_hdr common_hdr;
		uint32_t pkt_opcode; //12
		uint64_t pkt_res_buf; //20
	};

	struct xhunter1_req
	{
		struct xhunter1_req_hdr hdr;
		char body[0x270 - sizeof(struct xhunter1_req_hdr)];
	};

	//common response
	struct xhunter1_common_res
	{
		struct xhunter1_common_hdr hdr;
		DWORD dwStatus; //NTStatus from driver

		union
		{
			HANDLE hProc;
			DWORD dwProtectFlag;
			DWORD dwHookCallCnt;
			DWORD dwMaxParameter;
			UINT64 pPeb;

			char body[0x2F6 - sizeof(struct xhunter1_common_hdr)];
		};
	};

	struct xhunter1_proc_handle_req
	{
		DWORD dwProcessId;
		DWORD dwDesiredAccess;
	};

	struct PIDMAP_PARAM
	{
		ULONG pid;
		ULONG type;
	};

	struct PIDREMOVE_PARAM
	{
		ULONG pid;
	};

	struct xhunter1_proc_sethookstate
	{
		BYTE byHookState;
	};

	struct xhunter1_proc_GetProcessProtectFlag_req
	{
		ULONG pid;
	};

#pragma pack(pop)

	// Opaque handle for XHunter API Context
	typedef void* XH_HANDLE;

	// Connection / Lifecycle Methods
	// Pass NULL for driverPath to use default "%windir%\nirvana.sys"
	XH_HANDLE XHunter_Connect(const wchar_t* driverPath, bool exportDriver);
	void XHunter_Disconnect(XH_HANDLE hClient);
	int XHunter_GetLastError(XH_HANDLE hClient);
	bool XHunter_IsRunning(XH_HANDLE hClient);

	// API Methods
	NTSTATUS XHunter_OpenProcess(XH_HANDLE hClient, DWORD dwProcessId, DWORD dwDesiredAccess, HANDLE* phProcess);
	NTSTATUS XHunter_StartHandleHook(XH_HANDLE hClient);
	NTSTATUS XHunter_StopHandleHook(XH_HANDLE hClient);
	NTSTATUS XHunter_RegisterPid(XH_HANDLE hClient, DWORD dwPid, uint32_t flag);
	NTSTATUS XHunter_UnregisterPid(XH_HANDLE hClient, DWORD dwPid);
	NTSTATUS XHunter_GetProtectedProcessFlag(XH_HANDLE hClient, DWORD dwPid, DWORD* pFlag);
	NTSTATUS XHunter_RegisterReportReader(XH_HANDLE hClient);

#ifdef __cplusplus
}
#endif

#endif