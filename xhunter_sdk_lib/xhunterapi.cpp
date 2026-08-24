#include <phnt_windows.h>
#include <phnt.h>

#include <stdio.h>
#include <conio.h>
#include <strsafe.h>

#include <string>
#include <filesystem>
#include <fstream>
#include <memory>
#include <functional>

#include <xorstr.hpp>
#include <vmp/VMProtectSDK.h>
#include <nirvana/std_format_ext.h>
#include <misc/crypto.h>

#include "util.hpp"

#include "xhunterapi.h"
#include "xhunter1_sys_bin.h"

#pragma auto_inline(off)

namespace xhunterapi {

	typedef UINT(WINAPI* GETSYSTEMWOW64DIRECTORY)(LPTSTR, UINT);

	XHunterClient::XHunterClient() 
		: m_hDriver(INVALID_HANDLE_VALUE), 
		  m_lastError(0), 
		  m_selfRun(false) {
	}

	XHunterClient::~XHunterClient() {
		Disconnect();
	}

	int XHunterClient::GetLastError() const noexcept {
		return m_lastError;
	}

	bool XHunterClient::IsRunning() const noexcept {
		return util::is_service_running(m_serviceName);
	}

	void XHunterClient::Disconnect() noexcept {
		if (m_hDriver != INVALID_HANDLE_VALUE) {
			CloseHandle(m_hDriver);
			m_hDriver = INVALID_HANDLE_VALUE;
		}

		if (m_selfRun) {
			util::stop_service_entry(m_serviceName);
			m_selfRun = false;
		}
	}

	bool XHunterClient::Connect(std::filesystem::path driverPath, bool exportDriver) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);

		if (m_hDriver != INVALID_HANDLE_VALUE) {
			return true;
		}

		std::wstring pathStr = driverPath.wstring();
		DWORD required = ExpandEnvironmentStringsW(pathStr.c_str(), nullptr, 0);
		if (required > 1) {
			std::wstring expanded(required - 1, L'\0');
			ExpandEnvironmentStringsW(pathStr.c_str(), &expanded[0], required);
			driverPath = expanded;
		}

		driverPath = std::filesystem::absolute(driverPath);
		
		m_serviceName = driverPath.stem().wstring();
		m_driverPath = std::wstring(XSW("\\??\\")) + driverPath.wstring();

		if (!exportDriver) {
			m_selfRun = false;
			std::wstring devName = std::format_(XSW("\\\\.\\{}"), m_serviceName);
			m_hDriver = CreateFileW(devName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			if (m_hDriver == INVALID_HANDLE_VALUE) {
				m_lastError = GetLastError();
				return false;
			}

			VMP_END();
			return true;
		}

		if (!util::service_exists(m_serviceName)) {
			if (!util::create_service_entry(m_serviceName, m_serviceName, m_driverPath)) {
				m_lastError = 1;
				return false;
			}

			if (!ExportDriver(driverPath.wstring())) {
				m_lastError = 2;
				return false;
			}

			if (!util::start_service_entry(m_serviceName)) {
				m_lastError = 3;
				return false;
			}

			m_selfRun = true;
		} else {
			if (!util::is_service_running(m_serviceName)) {
				std::ifstream f(driverPath.wstring(), std::ios::binary);

				while (!f.is_open()) {
					if (!ExportDriver(driverPath.wstring())) {
						m_lastError = 5;
						return false;
					}

					if (!util::start_service_entry(m_serviceName)) {
						m_lastError = 7;
						return false;
					}

					break;
				}

				std::string xhunter_data;
				f.seekg(0, std::ios::end);
				xhunter_data.resize((size_t)f.tellg());
				f.seekg(0, std::ios::beg);
				f.read(&xhunter_data[0], xhunter_data.size());
				f.close();

				auto sum = crypto::hash(XSW("SHA512"), xhunter_data);
				auto sum_hex = crypto::bin2hex(sum);

				if (sum_hex != XSA("596d8a02a4dfbb0e71a985a8ef2b01242762bb518b60b0f23f83f1ac15dbf2619b1a1e8c93316e06f25ac989469aa3f5f5edfbdf2c4979394e68b6ab9d726d65")) {
					std::filesystem::remove(driverPath);

					if (!ExportDriver(driverPath.wstring())) {
						m_lastError = 5;
						return false;
					}
				}

				if (!util::start_service_entry(m_serviceName)) {
					m_lastError = 6;
					return false;
				}

				m_selfRun = true;
			}
		}

		std::wstring devName = std::format_(XSW("\\\\.\\{}"), m_serviceName);
		m_hDriver = CreateFileW(devName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (m_hDriver == INVALID_HANDLE_VALUE) {
			m_lastError = GetLastError();
			return false;
		}

		VMP_END();
		return true;
	}



	bool XHunterClient::ExportDriver(const std::wstring& path) const noexcept {
		std::ofstream f(path, std::ios::binary);

		if (!f.is_open()) {
			return false;
		}

		std::string dec_xhunter_data;
		dec_xhunter_data.resize(XHUNTER1_SYS_SIZE);
		memcpy(dec_xhunter_data.data(), XHUNTER1_SYS_DATA, XHUNTER1_SYS_SIZE);

		for (size_t i = 0; i < dec_xhunter_data.size(); i++) {
			dec_xhunter_data[i] ^= 0xFF;
		}

		f.write(dec_xhunter_data.data(), dec_xhunter_data.size());
		return true;
	}

	std::unique_ptr<xhunter1_common_res> XHunterClient::SendPacket(Opcode opcode, const void* body, size_t body_len) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		
		if (m_hDriver == INVALID_HANDLE_VALUE || body_len > (sizeof(((xhunter1_req*)NULL)->body))) {
			return nullptr;
		}

		xhunter1_req req = { 0 };
		req.hdr.common_hdr.pkt_size = 0x270;
		req.hdr.common_hdr.pkt_magic = 0x345821AB; //24
		req.hdr.common_hdr.pkt_req_id = rand();
		req.hdr.pkt_opcode = static_cast<uint32_t>(opcode);

		if (body != nullptr) {
			memcpy(req.body, body, body_len);
		}

		DWORD dwBytesWritten = 0;
		auto res = std::make_unique<xhunter1_common_res>();
		memset(res.get(), 0, sizeof(xhunter1_common_res));

		// This isn't optimal, but we need to keep the header size the same across both x86 and x86_64.
		req.hdr.pkt_res_buf = (uint64_t)res.get();

		if (!WriteFile(m_hDriver, &req, sizeof(xhunter1_req), &dwBytesWritten, NULL)) {
			return nullptr;
		}

		// Response packets have their own magic value.
		if (res->hdr.pkt_magic != 0x12121212) {
			return nullptr;
		}

		// The response buffer's "request ID" should be the bit-wise NOT'ed version of our request's ID.
		if (~res->hdr.pkt_req_id != req.hdr.common_hdr.pkt_req_id) {
			return nullptr;
		}

		VMP_END();
		return res;
	}

	xhunter::Result<HANDLE> XHunterClient::OpenProcess(DWORD dwProcessId, DWORD dwDesiredAccess) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		xhunter1_proc_handle_req handle_req = { 0 };
		handle_req.dwProcessId = dwProcessId;
		handle_req.dwDesiredAccess = dwDesiredAccess;

		auto res_packet = SendPacket(Opcode::OpenProcess, &handle_req, sizeof(xhunter1_proc_handle_req));

		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send OpenProcess packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected OpenProcess request"));
		}

		HANDLE out = res_packet->hProc;
		VMP_END();
		return out;
	}

	xhunter::Result<void> XHunterClient::StartHandleHook() noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 1;

		auto res_packet = SendPacket(Opcode::SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send StartHandleHook packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected StartHandleHook request"));
		}
		
		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::StopHandleHook() noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 0;

		auto res_packet = SendPacket(Opcode::SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send StopHandleHook packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected StopHandleHook request"));
		}
		
		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::RegisterPid(DWORD dwPid, PidFlag flag) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);

		PIDMAP_PARAM pidmap_req = { 0 };
		pidmap_req.pid = dwPid;
		pidmap_req.type = static_cast<ULONG>(flag);

		auto res_packet = SendPacket(Opcode::MapPid, &pidmap_req, sizeof(PIDMAP_PARAM));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send RegisterPid packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected RegisterPid request"));
		}

		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::UnregisterPid(DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		PIDREMOVE_PARAM pidremove_req = { 0 };
		pidremove_req.pid = dwPid;

		auto res_packet = SendPacket(Opcode::ClearPidFlags, &pidremove_req, sizeof(PIDREMOVE_PARAM));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send UnregisterPid packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected UnregisterPid request"));
		}

		VMP_END();
		return {};
	}

	xhunter::Result<DWORD> XHunterClient::GetProtectedProcessFlag(DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = dwPid;

		auto res_packet = SendPacket(Opcode::GetProtectFlag, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));

		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send GetProtectedProcessFlag packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected GetProtectedProcessFlag request"));
		}

		DWORD out = res_packet->dwProtectFlag;
		VMP_END();
		return out;
	}

	xhunter::Result<void> XHunterClient::RegisterReportReader() noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		//dummy var, xhunter not read it
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = 0;

		auto res_packet = SendPacket(Opcode::RegisterReportReader, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send RegisterReportReader packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected RegisterReportReader request"));
		}

		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::AuthenticateCaller() noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		auto res_reg = RegisterReportReader();
		if (!res_reg) {
			return res_reg;
		}

		const DWORD self_pid = GetCurrentProcessId();
		auto res_map = RegisterPid(self_pid, PidFlag::Protected);
		if (!res_map) {
			return res_map;
		}

		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::ReadKernelMemory(uint64_t srcKernelVa, void* dstUserVa, uint32_t size) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		if (!dstUserVa || !size) {
			X_FAIL_MSG(XSA("Invalid arguments for ReadKernelMemory"));
		}

		xhunter1_proc_ReadKernelMemory_req req = { 0 };
		req.srcKernelVa = srcKernelVa;
		req.dstUserVa = reinterpret_cast<uint64_t>(dstUserVa);
		req.size = size;

		auto res_packet = SendPacket(Opcode::ReadKernelMemory, &req, sizeof(xhunter1_proc_ReadKernelMemory_req));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send ReadKernelMemory packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected ReadKernelMemory request"));
		}

		VMP_END();
		return {};
	}

	xhunter::Result<void> XHunterClient::ReadProcessMemory(HANDLE hProcess, uint64_t srcUserVa, void* dstUserVa, uint32_t size) noexcept {
		VMP_BEGIN_MUTATION(__FUNCTION__);
		if (!hProcess || !dstUserVa || !size) {
			X_FAIL_MSG(XSA("Invalid arguments for ReadProcessMemory"));
		}

		xhunter1_proc_ReadProcessMemory_req req = { 0 };
		req.hProcess = hProcess;
		req.srcUserVa = srcUserVa;
		req.dstUserVa = reinterpret_cast<uint64_t>(dstUserVa);
		req.size = size;

		auto res_packet = SendPacket(Opcode::ReadProcessMemory, &req, sizeof(xhunter1_proc_ReadProcessMemory_req));
		if (!res_packet) {
			X_FAIL_MSG(XSA("Failed to send ReadProcessMemory packet"));
		}

		if (res_packet->dwStatus != STATUS_SUCCESS) {
			X_FAIL(res_packet->dwStatus, XSA("Driver rejected ReadProcessMemory request"));
		}

		VMP_END();
		return {};
	}
}