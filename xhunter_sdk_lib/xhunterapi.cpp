#include <phnt_windows.h>
#include <phnt.h>

#include <stdio.h>
#include <conio.h>
#include <strsafe.h>

#include <xorstr.hpp>
#include <vmp/VMProtectSDK.h>

#include "util.hpp"
#include "xhunterapi.h"
#include "xhunter1_sys_bin.h"

// Note: Removing STL crypto to guarantee no _ITERATOR_DEBUG_LEVEL leakage
// We will do a basic byte-comparison or use BCrypt if strictly needed.
// For the nirvana.sys hash check, we can just compare the byte array directly since we decrypted it.

#pragma auto_inline(off)

struct XHunterContext {
	HANDLE m_hDriver;
	int m_lastError;
	bool m_selfRun;
	wchar_t m_serviceName[MAX_PATH];
	wchar_t m_driverPath[MAX_PATH];
};

static bool ExportDriver(const wchar_t* path) noexcept {
	HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	char* dec_xhunter_data = (char*)malloc(XHUNTER1_SYS_SIZE);
	if (!dec_xhunter_data) {
		CloseHandle(hFile);
		return false;
	}

	memcpy(dec_xhunter_data, XHUNTER1_SYS_DATA, XHUNTER1_SYS_SIZE);

	for (size_t i = 0; i < XHUNTER1_SYS_SIZE; i++) {
		dec_xhunter_data[i] ^= 0xFF;
	}

	DWORD dwWritten = 0;
	WriteFile(hFile, dec_xhunter_data, XHUNTER1_SYS_SIZE, &dwWritten, NULL);
	
	free(dec_xhunter_data);
	CloseHandle(hFile);
	return true;
}

static xhunter1_common_res* SendPacketInternal(XHunterContext* ctx, Opcode opcode, const void* body, size_t body_len) noexcept {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	
	if (ctx->m_hDriver == INVALID_HANDLE_VALUE || body_len > (sizeof(((xhunter1_req*)NULL)->body))) {
		return NULL;
	}

	xhunter1_req req = { 0 };
	req.hdr.common_hdr.pkt_size = 0x270;
	req.hdr.common_hdr.pkt_magic = 0x345821AB; //24
	req.hdr.common_hdr.pkt_req_id = rand();
	req.hdr.pkt_opcode = static_cast<uint32_t>(opcode);

	if (body != NULL) {
		memcpy(req.body, body, body_len);
	}

	DWORD dwBytesWritten = 0;
	xhunter1_common_res* res = (xhunter1_common_res*)malloc(sizeof(xhunter1_common_res));
	if (!res) return NULL;
	
	memset(res, 0, sizeof(xhunter1_common_res));

	// This isn't optimal, but we need to keep the header size the same across both x86 and x86_64.
	req.hdr.pkt_res_buf = (uint64_t)res;

	if (!WriteFile(ctx->m_hDriver, &req, sizeof(xhunter1_req), &dwBytesWritten, NULL)) {
		free(res);
		return NULL;
	}

	// Response packets have their own magic value.
	if (res->hdr.pkt_magic != 0x12121212) {
		free(res);
		return NULL;
	}

	// The response buffer's "request ID" should be the bit-wise NOT'ed version of our request's ID.
	if (~res->hdr.pkt_req_id != req.hdr.common_hdr.pkt_req_id) {
		free(res);
		return NULL;
	}

	VMP_END();
	return res;
}

#ifdef __cplusplus
extern "C" {
#endif

XH_HANDLE XHunter_Connect(const wchar_t* driverPath, bool exportDriver) {
	VMP_BEGIN_MUTATION(__FUNCTION__);

	XHunterContext* ctx = (XHunterContext*)malloc(sizeof(XHunterContext));
	if (!ctx) return NULL;

	ctx->m_hDriver = INVALID_HANDLE_VALUE;
	ctx->m_lastError = 0;
	ctx->m_selfRun = false;
	memset(ctx->m_serviceName, 0, sizeof(ctx->m_serviceName));
	memset(ctx->m_driverPath, 0, sizeof(ctx->m_driverPath));

	wchar_t resolvedPath[MAX_PATH] = { 0 };
	const wchar_t* targetPath = driverPath;

	if (!targetPath) {
		targetPath = L"%windir%\\nirvana.sys";
	}

	DWORD required = ExpandEnvironmentStringsW(targetPath, resolvedPath, MAX_PATH);
	if (required == 0 || required > MAX_PATH) {
		// expansion failed or path too long
		wcsncpy_s(resolvedPath, targetPath, MAX_PATH - 1);
	}

	wchar_t absPath[MAX_PATH] = { 0 };
	if (GetFullPathNameW(resolvedPath, MAX_PATH, absPath, NULL) == 0) {
		wcsncpy_s(absPath, resolvedPath, MAX_PATH - 1);
	}

	// Extract stem for serviceName
	const wchar_t* bs = wcsrchr(absPath, L'\\');
	const wchar_t* fs = wcsrchr(absPath, L'/');
	const wchar_t* filename = (bs > fs) ? bs + 1 : ((fs > bs) ? fs + 1 : absPath);
	const wchar_t* dot = wcsrchr(filename, L'.');
	
	if (dot) {
		size_t len = dot - filename;
		if (len >= MAX_PATH) len = MAX_PATH - 1;
		wcsncpy_s(ctx->m_serviceName, filename, len);
	} else {
		wcscpy_s(ctx->m_serviceName, filename);
	}

	StringCbPrintfW(ctx->m_driverPath, sizeof(ctx->m_driverPath), L"\\??\\%s", absPath);

	if (!exportDriver) {
		ctx->m_selfRun = false;
		wchar_t devName[MAX_PATH];
		StringCbPrintfW(devName, sizeof(devName), L"\\\\.\\%s", ctx->m_serviceName);
		
		ctx->m_hDriver = CreateFileW(devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (ctx->m_hDriver == INVALID_HANDLE_VALUE) {
			ctx->m_lastError = GetLastError();
			free(ctx);
			return NULL;
		}

		VMP_END();
		return ctx;
	}

	if (!util::service_exists(ctx->m_serviceName)) {
		if (!util::create_service_entry(ctx->m_serviceName, ctx->m_serviceName, ctx->m_driverPath)) {
			ctx->m_lastError = 1;
			free(ctx);
			return NULL;
		}

		if (!ExportDriver(absPath)) {
			ctx->m_lastError = 2;
			free(ctx);
			return NULL;
		}

		if (!util::start_service_entry(ctx->m_serviceName)) {
			ctx->m_lastError = 3;
			free(ctx);
			return NULL;
		}

		ctx->m_selfRun = true;
	} else {
		if (!util::is_service_running(ctx->m_serviceName)) {
			HANDLE hFile = CreateFileW(absPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			while (hFile == INVALID_HANDLE_VALUE) {
				if (!ExportDriver(absPath)) {
					ctx->m_lastError = 5;
					free(ctx);
					return NULL;
				}

				if (!util::start_service_entry(ctx->m_serviceName)) {
					ctx->m_lastError = 7;
					free(ctx);
					return NULL;
				}

				break;
			}

			if (hFile != INVALID_HANDLE_VALUE) {
				// To avoid STL and BCrypt hashing overhead for a static driver file, 
				// we just read its bytes and compare it to decrypted XHUNTER1_SYS_DATA.
				DWORD fileSize = GetFileSize(hFile, NULL);
				char* file_data = (char*)malloc(fileSize);
				DWORD dwRead = 0;
				bool changed = true;

				if (file_data && ReadFile(hFile, file_data, fileSize, &dwRead, NULL) && fileSize == XHUNTER1_SYS_SIZE) {
					char* dec_xhunter_data = (char*)malloc(XHUNTER1_SYS_SIZE);
					if (dec_xhunter_data) {
						memcpy(dec_xhunter_data, XHUNTER1_SYS_DATA, XHUNTER1_SYS_SIZE);
						for (size_t i = 0; i < XHUNTER1_SYS_SIZE; i++) {
							dec_xhunter_data[i] ^= 0xFF;
						}
						
						if (memcmp(file_data, dec_xhunter_data, XHUNTER1_SYS_SIZE) == 0) {
							changed = false;
						}
						free(dec_xhunter_data);
					}
				}
				
				if (file_data) free(file_data);
				CloseHandle(hFile);

				if (changed) {
					DeleteFileW(absPath);
					if (!ExportDriver(absPath)) {
						ctx->m_lastError = 5;
						free(ctx);
						return NULL;
					}
				}
			}

			if (!util::start_service_entry(ctx->m_serviceName)) {
				ctx->m_lastError = 6;
				free(ctx);
				return NULL;
			}

			ctx->m_selfRun = true;
		}
	}

	wchar_t devName[MAX_PATH];
	StringCbPrintfW(devName, sizeof(devName), L"\\\\.\\%s", ctx->m_serviceName);
	ctx->m_hDriver = CreateFileW(devName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ctx->m_hDriver == INVALID_HANDLE_VALUE) {
		ctx->m_lastError = GetLastError();
		free(ctx);
		return NULL;
	}

	VMP_END();
	return ctx;
}

void XHunter_Disconnect(XH_HANDLE hClient) {
	if (!hClient) return;
	XHunterContext* ctx = (XHunterContext*)hClient;

	if (ctx->m_hDriver != INVALID_HANDLE_VALUE) {
		CloseHandle(ctx->m_hDriver);
		ctx->m_hDriver = INVALID_HANDLE_VALUE;
	}

	if (ctx->m_selfRun) {
		util::stop_service_entry(ctx->m_serviceName);
		ctx->m_selfRun = false;
	}

	free(ctx);
}

int XHunter_GetLastError(XH_HANDLE hClient) {
	if (!hClient) return -1;
	return ((XHunterContext*)hClient)->m_lastError;
}

bool XHunter_IsRunning(XH_HANDLE hClient) {
	if (!hClient) return false;
	return util::is_service_running(((XHunterContext*)hClient)->m_serviceName);
}

NTSTATUS XHunter_OpenProcess(XH_HANDLE hClient, DWORD dwProcessId, DWORD dwDesiredAccess, HANDLE* phProcess) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient || !phProcess) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	xhunter1_proc_handle_req handle_req = { 0 };
	handle_req.dwProcessId = dwProcessId;
	handle_req.dwDesiredAccess = dwDesiredAccess;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_OpenProcess, &handle_req, sizeof(xhunter1_proc_handle_req));

	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	if (NT_SUCCESS(st)) {
		*phProcess = res_packet->hProc;
	}
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_StartHandleHook(XH_HANDLE hClient) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	xhunter1_proc_sethookstate hookstate_req = { 0 };
	hookstate_req.byHookState = 1;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_StopHandleHook(XH_HANDLE hClient) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	xhunter1_proc_sethookstate hookstate_req = { 0 };
	hookstate_req.byHookState = 0;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_RegisterPid(XH_HANDLE hClient, DWORD dwPid, uint32_t flag) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;

	PIDMAP_PARAM pidmap_req = { 0 };
	pidmap_req.pid = dwPid;
	pidmap_req.type = flag;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_MapPid, &pidmap_req, sizeof(PIDMAP_PARAM));
	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_UnregisterPid(XH_HANDLE hClient, DWORD dwPid) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	PIDREMOVE_PARAM pidremove_req = { 0 };
	pidremove_req.pid = dwPid;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_UnmapPid, &pidremove_req, sizeof(PIDREMOVE_PARAM));
	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_GetProtectedProcessFlag(XH_HANDLE hClient, DWORD dwPid, DWORD* pFlag) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient || !pFlag) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
	protect_req.pid = dwPid;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_GetProtectFlag, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));

	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	if (NT_SUCCESS(st)) {
		*pFlag = res_packet->dwProtectFlag;
	}
	free(res_packet);

	VMP_END();
	return st;
}

NTSTATUS XHunter_RegisterReportReader(XH_HANDLE hClient) {
	VMP_BEGIN_MUTATION(__FUNCTION__);
	if (!hClient) return STATUS_INVALID_PARAMETER;

	XHunterContext* ctx = (XHunterContext*)hClient;
	//dummy var, xhunter not read it
	xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
	protect_req.pid = 0;

	xhunter1_common_res* res_packet = SendPacketInternal(ctx, Opcode_RegisterReportReader, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));
	if (!res_packet) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS st = res_packet->dwStatus;
	free(res_packet);

	VMP_END();
	return st;
}

#ifdef __cplusplus
}
#endif