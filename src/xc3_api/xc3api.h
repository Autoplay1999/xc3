#pragma once
#pragma comment(lib, "ntdll.lib")

#ifndef XC3_API_H
#define XC3_API_H

#include <Windows.h>
#include <stdint.h>
#include <memory>
#include <optional>
#include <string>
#include <filesystem>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#include "error.hpp"

namespace xc3api
{
	enum class PidFlag : uint32_t {
		Allow = 1,
		Deny = 2,
		Unprotect = 4,
		Protected = 8,
		ReportAuthenticated = 0x40000000,
		ReportProcess = 0x80000000
	};

	inline PidFlag operator|(PidFlag a, PidFlag b) {
		return static_cast<PidFlag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
	}

	enum class Opcode : uint32_t {
		Ping = 774,
		MapPid = 775,
		ClearPidFlags = 776,
		RegisterReportReader = 777,
		UnregisterReportReader = 778,
		EnumTrustedPids = 779,
		SetHookState = 782,
		QueryVersion = 783,
		OpenProcess = 785,
		QueryCounter = 786,
		ReadProcessMemory = 787,
		ReadKernelMemory = 788,
		QueryProcessInformation = 791,
		GetProtectFlag = 797,
		CloseRemoteHandle = 800,
		InitWin32k = 801,
		QueryPte = 805,
		CreateKernelFile = 810,
		PopulateTrustCache = 813,
		InjectShellcode = 820
	};

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

	struct xhunter1_proc_ReadKernelMemory_req
	{
		uint64_t srcKernelVa;
		uint64_t dstUserVa;
		uint32_t size;
	};

	struct xhunter1_proc_ReadProcessMemory_req
	{
		HANDLE hProcess;
		uint64_t srcUserVa;
		uint64_t dstUserVa;
		uint32_t size;
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

	class XC3Client {
	public:
		XC3Client();
		~XC3Client();

		// Prevent copying
		XC3Client(const XC3Client&) = delete;
		XC3Client& operator=(const XC3Client&) = delete;

		// Connection / Lifecycle Methods
		bool Connect(std::filesystem::path driverPath = "%windir%\\nirvana.sys", bool exportDriver = true) noexcept;
		void Disconnect() noexcept;
		bool IsRunning() const noexcept;
		int GetLastError() const noexcept;

		// API Methods
		xc3::Result<HANDLE> OpenProcess(DWORD dwProcessId, DWORD dwDesiredAccess) noexcept;
		xc3::Result<void> StartHandleHook() noexcept;
		xc3::Result<void> StopHandleHook() noexcept;
		xc3::Result<void> RegisterPid(DWORD dwPid, PidFlag flag) noexcept;
		xc3::Result<void> UnregisterPid(DWORD dwPid) noexcept;
		xc3::Result<DWORD> GetProtectedProcessFlag(DWORD dwPid) noexcept;
		xc3::Result<void> RegisterReportReader() noexcept;
		xc3::Result<void> AuthenticateCaller() noexcept;
		xc3::Result<void> ReadKernelMemory(uint64_t srcKernelVa, void* dstUserVa, uint32_t size) noexcept;
		xc3::Result<void> ReadProcessMemory(HANDLE hProcess, uint64_t srcUserVa, void* dstUserVa, uint32_t size) noexcept;

	private:
		HANDLE m_hDriver;
		int m_lastError;
		bool m_selfRun;

		std::wstring m_serviceName;
		std::wstring m_driverPath;

		std::unique_ptr<xhunter1_common_res> SendPacket(Opcode opcode, const void* body, size_t body_len) noexcept;

		// Utility Helpers
		bool ExportDriver(const std::wstring& path) const noexcept;
	};
}

#endif