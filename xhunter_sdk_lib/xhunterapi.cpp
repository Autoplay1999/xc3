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

	XHunterClient::XHunterClient() : m_hDriver(INVALID_HANDLE_VALUE), m_lastError(0), m_selfRun(false) {
	}

	XHunterClient::~XHunterClient() {
		Disconnect();
	}

	int XHunterClient::GetLastError() const noexcept {
		return m_lastError;
	}

	bool XHunterClient::IsRunning() const noexcept {
		auto IsMyServiceRunning = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
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
		};

		std::wstring xhunter_name = XSW("xhunter1");
		return IsMyServiceRunning(xhunter_name);
	}

	void XHunterClient::Disconnect() noexcept {
		if (m_hDriver != INVALID_HANDLE_VALUE) {
			CloseHandle(m_hDriver);
			m_hDriver = INVALID_HANDLE_VALUE;
		}

		if (m_selfRun) {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (scManager) {
				SC_HANDLE service = OpenService(scManager, XSW("xhunter1"), SERVICE_STOP | SERVICE_QUERY_STATUS);
				if (service) {
					SERVICE_STATUS status;
					ControlService(service, SERVICE_CONTROL_STOP, &status);
					CloseServiceHandle(service);
				}
				CloseServiceHandle(scManager);
			}
			m_selfRun = false;
		}
	}

	bool XHunterClient::Connect() noexcept {
		VMP_BEGIN_MUTATION("nOTF0Goo0hpj3Oi6KL6GzjC8CVElL5lqQmRmw3oxR4FGzPyHSlC2K58o9x3KzBCD");

		if (m_hDriver != INVALID_HANDLE_VALUE) {
			return true;
		}

		auto ExportXHunter = [](std::wstring& path) -> bool {
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
		};

		auto MyServiceExists = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
			bool exists = service != nullptr;

			if (service) CloseServiceHandle(service);
			CloseServiceHandle(scManager);

			return exists;
		};

		auto IsMyServiceRunning = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
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
		};

		auto CreateMyService = [](const std::wstring& serviceName, const std::wstring& displayName, const std::wstring& exePath) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
			if (!scManager) {
				return false;
			}

			SC_HANDLE service = CreateService(
				scManager,
				serviceName.c_str(),
				displayName.c_str(),
				SERVICE_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL,
				exePath.c_str(),
				nullptr, nullptr, nullptr, nullptr, nullptr);

			if (!service) {
				CloseServiceHandle(scManager);
				return false;
			}

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);
			return true;
		};

		auto StartMyService = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_START);
			if (!service) {
				CloseServiceHandle(scManager);
				return false;
			}

			bool success = StartService(service, 0, nullptr);

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);
			return success;
		};

		std::wstring xhunter_name = XSW("xhunter1");
		std::wstring xhunter_path = XSW("\\??\\C:\\Windows\\xhunter1.sys");

		if (!MyServiceExists(xhunter_name.c_str())) {
			if (!CreateMyService(xhunter_name.c_str(), xhunter_name.c_str(), xhunter_path.c_str())) {
				m_lastError = 1;
				return false;
			}

			if (!ExportXHunter(xhunter_path)) {
				m_lastError = 2;
				return false;
			}

			if (!StartMyService(xhunter_name.c_str())) {
				m_lastError = 3;
				return false;
			}

			m_selfRun = true;
		} else {
			if (!IsMyServiceRunning(xhunter_name.c_str())) {
				std::ifstream f(xhunter_path, std::ios::binary);

				while (!f.is_open()) {
					if (!ExportXHunter(xhunter_path)) {
						m_lastError = 5;
						return false;
					}

					if (!StartMyService(XSW("xhunter1"))) {
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
					std::filesystem::remove(xhunter_path);

					if (!ExportXHunter(xhunter_path)) {
						m_lastError = 5;
						return false;
					}
				}

				if (!StartMyService(XSW("xhunter1"))) {
					m_lastError = 6;
					return false;
				}

				m_selfRun = true;
			}
		}

		m_hDriver = CreateFileW(XSW("\\\\.\\xhunter1"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (m_hDriver == INVALID_HANDLE_VALUE) {
			m_lastError = GetLastError();
			return false;
		}

		VMP_END();
		return true;
	}

	std::unique_ptr<xhunter1_common_res> XHunterClient::SendPacket(Opcode opcode, const void* body, size_t body_len) noexcept {
		VMP_BEGIN_MUTATION("Woe5xsiJCS0zHoFalUGhpmK5Q86clmtMky68uJRIqDBF1FhMNmxB1tBvGdUR1NSv");
		
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

	ApiResult<HANDLE> XHunterClient::OpenProcess(DWORD dwProcessId, DWORD dwDesiredAccess) noexcept {
		VMP_BEGIN_MUTATION("gIvDgOxc5egDhIIoF3ZF92tyKUbr6F1hHriv8BmtzVQK1bmXXwo6b1jGlU0cmf8r");
		xhunter1_proc_handle_req handle_req = { 0 };
		handle_req.dwProcessId = dwProcessId;
		handle_req.dwDesiredAccess = dwDesiredAccess;

		auto res_packet = SendPacket(Opcode::OpenProcess, &handle_req, sizeof(xhunter1_proc_handle_req));

		ApiResult<HANDLE> result = { STATUS_UNSUCCESSFUL, std::nullopt };

		if (res_packet) {
			result.status = res_packet->dwStatus;
			if (res_packet->dwStatus == STATUS_SUCCESS) {
				result.value = res_packet->hProc;
			}
		}

		VMP_END();
		return result;
	}

	VoidResult XHunterClient::StartHandleHook() noexcept {
		VMP_BEGIN_MUTATION("dWEs7DNFCvPRajf4np3hy0gTsXKzNk2FNy9SQJYcMBXLICUEJcR2JZKn7lsVR7Ko");
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 1;

		auto res_packet = SendPacket(Opcode::SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
		VoidResult result = { res_packet ? static_cast<NTSTATUS>(res_packet->dwStatus) : STATUS_UNSUCCESSFUL };
		
		VMP_END();
		return result;
	}

	VoidResult XHunterClient::StopHandleHook() noexcept {
		VMP_BEGIN_MUTATION("1xqJaNfjOV4JGndjNjiejC4UJYxquAJpdjiWOi37qqCCEQz3le3jRs5ZJB2kObe3");
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 0;

		auto res_packet = SendPacket(Opcode::SetHookState, &hookstate_req, sizeof(xhunter1_proc_sethookstate));
		VoidResult result = { res_packet ? static_cast<NTSTATUS>(res_packet->dwStatus) : STATUS_UNSUCCESSFUL };
		
		VMP_END();
		return result;
	}

	VoidResult XHunterClient::RegisterPid(DWORD dwPid, PidFlag flag) noexcept {
		VMP_BEGIN_MUTATION("4RvApJPF9ibU59y7PkfHTlzroi29GBsb8Wi10M4f5ef9Bk8rYNvFX64L97PTMvou");

		PIDMAP_PARAM pidmap_req = { 0 };
		pidmap_req.pid = dwPid;
		pidmap_req.type = static_cast<ULONG>(flag);

		auto res_packet = SendPacket(Opcode::MapPid, &pidmap_req, sizeof(PIDMAP_PARAM));
		VoidResult result = { res_packet ? static_cast<NTSTATUS>(res_packet->dwStatus) : STATUS_UNSUCCESSFUL };

		VMP_END();
		return result;
	}

	VoidResult XHunterClient::UnregisterPid(DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION("ItdSaN4rdgD2Pb1bRW1FV733AFz2z0c6V1MqURBSiaASSjBdGRVyfzl8BKchYuSu");
		PIDREMOVE_PARAM pidremove_req = { 0 };
		pidremove_req.pid = dwPid;

		auto res_packet = SendPacket(Opcode::UnmapPid, &pidremove_req, sizeof(PIDREMOVE_PARAM));
		VoidResult result = { res_packet ? static_cast<NTSTATUS>(res_packet->dwStatus) : STATUS_UNSUCCESSFUL };

		VMP_END();
		return result;
	}

	ApiResult<DWORD> XHunterClient::GetProtectedProcessFlag(DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION("UtDiWdNwqt3d741rBBZwyaN951nE9K8j1gKMMoU84MTQ6vWK2dpNfO9jzUsIiEeJ");
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = dwPid;

		auto res_packet = SendPacket(Opcode::GetProtectFlag, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));

		ApiResult<DWORD> result = { STATUS_UNSUCCESSFUL, std::nullopt };

		if (res_packet) {
			result.status = res_packet->dwStatus;
			if (res_packet->dwStatus == STATUS_SUCCESS) {
				result.value = res_packet->dwProtectFlag;
			}
		}

		VMP_END();
		return result;
	}

	VoidResult XHunterClient::RegisterReportReader() noexcept {
		VMP_BEGIN_MUTATION("zPfYNEXt171cm2LtZKGKVQ6o1K2ttAEiSTfJe0uDIDg95z24vGAWm2Vb2V1zUA8B");
		//dummy var, xhunter not read it
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = 0;

		auto res_packet = SendPacket(Opcode::RegisterReportReader, &protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));
		VoidResult result = { res_packet ? static_cast<NTSTATUS>(res_packet->dwStatus) : STATUS_UNSUCCESSFUL };

		VMP_END();
		return result;
	}
}