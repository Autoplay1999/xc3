#pragma once
#pragma comment(lib, "ntdll.lib")

#ifndef XHUNTER_API_H
#define XHUNTER_API_H

#define ZXTF_PID_ALLOW			1
#define ZXTF_PID_DENY			2
#define ZXTF_PID_UNPROTECT		4
#define ZXTF_PID_PROTECTED		8

#define ZXTF_PID_REPORT_AUTHENTICATED 0x40000000
#define ZXTF_PID_REPORT_PROCESS 0x80000000

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#include <stdint.h>

namespace xhunterapi
{
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
		xhunter1_common_hdr common_hdr;
		uint32_t pkt_opcode; //12
		uint64_t pkt_res_buf; //20
	};

	struct xhunter1_req
	{
		xhunter1_req_hdr hdr;
		char body[0x270 - sizeof(hdr)];
	};

	//common response
	struct xhunter1_common_res
	{
		xhunter1_common_hdr hdr;
		DWORD dwStatus; //NTStatus from driver

		union
		{
			HANDLE hProc;
			DWORD dwProtectFlag;
			DWORD dwHookCallCnt;
			DWORD dwMaxParameter;
			UINT64 pPeb;

			char body[0x2F6 - sizeof(hdr)];
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

	//Functions
	HANDLE get_xhunter1_handle()noexcept;
	HANDLE XOpenProcess(HANDLE hDriver, DWORD dwProcessId, DWORD dwDesiredAccess)noexcept;
	VOID StartHandleHook(HANDLE hDriver)noexcept;
	VOID StopHandleHook(HANDLE hDriver)noexcept;
	VOID RegisterPid(HANDLE hDriver, DWORD dwPid, ULONG dwFlag)noexcept;
	VOID UnregisterPid(HANDLE hDriver, DWORD dwPid)noexcept;
	DWORD GetProtectedProcessFlag(HANDLE hDriver, DWORD dwPid)noexcept;
	VOID XRegisterReportReader(HANDLE hDriver)noexcept;

	int get_last_error()noexcept;

	bool is_xhunter_running() noexcept;
}

#endif