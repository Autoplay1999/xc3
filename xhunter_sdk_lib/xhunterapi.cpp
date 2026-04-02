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
	HANDLE xHunterHandle = INVALID_HANDLE_VALUE;

	std::shared_ptr<void> xHunterAutoStop;

	int LastError;

	typedef UINT(WINAPI* GETSYSTEMWOW64DIRECTORY)(LPTSTR, UINT);

	xhunter1_req* build_xhunter1_packet(uint32_t opcode, char* body, size_t body_len) noexcept {
		VMP_BEGIN_MUTATION("epiE5bch3svSpT62d52hqYtj2VvyYnYHK6Awz0ZA2Sl8LcNAKfR7Os8eyg0Yvxic");

		if (body_len > (sizeof(((xhunter1_req*)NULL)->body))) {
			return NULL;
		}

		xhunter1_req* req = new xhunter1_req();
		memset(req, 0, sizeof(xhunter1_req));

		req->hdr.common_hdr.pkt_size = 0x270;
		req->hdr.common_hdr.pkt_magic = 0x345821AB; //24
		req->hdr.common_hdr.pkt_req_id = rand();
		req->hdr.pkt_opcode = opcode;

		if (body != NULL) {
			memcpy(req->body, body, body_len);
		}

		VMP_END();
		return req;
	}

	xhunter1_common_res* send_xhunter1_packet(HANDLE hDriver, xhunter1_req* req) noexcept  {
		VMP_BEGIN_MUTATION("Woe5xsiJCS0zHoFalUGhpmK5Q86clmtMky68uJRIqDBF1FhMNmxB1tBvGdUR1NSv");

		DWORD dwBytesWritten = 0;
		xhunter1_common_res* res = new xhunter1_common_res();
		memset(res, 0, sizeof(xhunter1_common_res));

		// This isn't optimal, but we need to keep the header size the same across both x86 and x86_64.
		req->hdr.pkt_res_buf = (uint64_t)res;

		if (!WriteFile(hDriver, req, sizeof(xhunter1_req), &dwBytesWritten, NULL)) {
			return NULL;
		}

		// The driver returns the response length as dwBytesWritten for some reason...
		//if (dwBytesWritten != sizeof(xhunter1_common_res)) 
		//{
		//	return NULL;
		//}

		// Response packets have their own magic value.
		if (res->hdr.pkt_magic != 0x12121212) {
			return NULL;
		}

		// The response buffer's "request ID" should be the bit-wise NOT'ed version of our request's ID.
		if (~res->hdr.pkt_req_id != req->hdr.common_hdr.pkt_req_id) {
			return NULL;
		}

		free(req);

		VMP_END();
		return res;
	}

	bool is_xhunter_running() noexcept {
		auto IsMyServiceRunning = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				//PrintError("OpenSCManager failed");
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
			if (!service) {
				//PrintError("OpenService failed");
				CloseServiceHandle(scManager);
				return false;
			}

			SERVICE_STATUS_PROCESS status;
			DWORD bytesNeeded;
			bool running = false;

			if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
				running = (status.dwCurrentState == SERVICE_RUNNING);
			} else {
				//PrintError("QueryServiceStatusEx failed");
			}

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);

			return running;
		};

		std::wstring xhunter_name = XSW("xhunter1");

		return IsMyServiceRunning(xhunter_name);
	}

	int get_last_error() noexcept {
		return LastError;
	}

	HANDLE get_xhunter1_handle() noexcept {
		VMP_BEGIN_MUTATION("nOTF0Goo0hpj3Oi6KL6GzjC8CVElL5lqQmRmw3oxR4FGzPyHSlC2K58o9x3KzBCD");

		if (xHunterHandle != INVALID_HANDLE_VALUE) {
			return xHunterHandle;
		}

		bool SelfRun = false;

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
				//PrintError("OpenSCManager failed");
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
				//PrintError("OpenSCManager failed");
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
			if (!service) {
				//PrintError("OpenService failed");
				CloseServiceHandle(scManager);
				return false;
			}

			SERVICE_STATUS_PROCESS status;
			DWORD bytesNeeded;
			bool running = false;

			if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
				running = (status.dwCurrentState == SERVICE_RUNNING);
			} else {
				//PrintError("QueryServiceStatusEx failed");
			}

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);

			return running;
		};

		auto CreateMyService = [](const std::wstring& serviceName, const std::wstring& displayName, const std::wstring& exePath) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
			if (!scManager) {
				//PrintError("OpenSCManager failed");
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
				//PrintError("CreateService failed");
				CloseServiceHandle(scManager);
				return false;
			}

			//std::wcout << L"Service created successfully." << std::endl;

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);
			return true;
		};

		auto StartMyService = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				//PrintError("OpenSCManager failed");
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_START);
			if (!service) {
				//PrintError("OpenService failed");
				CloseServiceHandle(scManager);
				return false;
			}

			bool success = StartService(service, 0, nullptr);
			if (!success) {
				//PrintError("StartService failed");
			} else {
				//std::wcout << L"Service started." << std::endl;
			}

			CloseServiceHandle(service);
			CloseServiceHandle(scManager);
			return success;
		};

		auto StopMyService = [](const std::wstring& serviceName) -> bool {
			SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
			if (!scManager) {
				//PrintError("OpenSCManager failed");
				return false;
			}

			SC_HANDLE service = OpenService(scManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
			if (!service) {
				//PrintError("OpenService failed");
				CloseServiceHandle(scManager);
				return false;
			}

			SERVICE_STATUS status;
			if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
				//PrintError("ControlService failed");
				CloseServiceHandle(service);
				CloseServiceHandle(scManager);
				return false;
			}

			//std::wcout << L"Service stopped." << std::endl;
			CloseServiceHandle(service);
			CloseServiceHandle(scManager);
			return true;
		};

		std::wstring xhunter_name = XSW("xhunter1");

		std::wstring xhunter_path = XSW("\\??\\C:\\Windows\\xhunter1.sys");

		if (!MyServiceExists(xhunter_name.c_str())) {
			if (!CreateMyService(xhunter_name.c_str(), xhunter_name.c_str(), xhunter_path.c_str())) {
				LastError = 1;
				return INVALID_HANDLE_VALUE;
			}

			if (!ExportXHunter(xhunter_path)) {
				LastError = 2;
				return INVALID_HANDLE_VALUE;
			}

			if (!StartMyService(xhunter_name.c_str())) {
				LastError = 3;
				return INVALID_HANDLE_VALUE;
			}

			SelfRun = true;
		} else {
			if (!IsMyServiceRunning(xhunter_name.c_str())) {
				std::ifstream f(xhunter_path, std::ios::binary);

				while (!f.is_open()) {
					if (!ExportXHunter(xhunter_path)) {
						LastError = 5;
						return INVALID_HANDLE_VALUE;
					}

					if (!StartMyService(XSW("xhunter1"))) {
						LastError = 7;
						return INVALID_HANDLE_VALUE;
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
						LastError = 5;
						return INVALID_HANDLE_VALUE;
					}
				}

				if (!StartMyService(XSW("xhunter1"))) {
					LastError = 6;
					return INVALID_HANDLE_VALUE;
				}

				SelfRun = true;
			}
		}

		xHunterHandle = CreateFileW(XSW("\\\\.\\xhunter1"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (SelfRun && xHunterHandle != INVALID_HANDLE_VALUE) {
			xHunterAutoStop = std::shared_ptr<void>(nullptr, [&](auto p) { StopMyService(XSW("xhunter1")); });
		}

		VMP_END();
		return xHunterHandle;
	}

	HANDLE XOpenProcess(HANDLE hDriver, DWORD dwProcessId, DWORD dwDesiredAccess) noexcept {
		VMP_BEGIN_MUTATION("gIvDgOxc5egDhIIoF3ZF92tyKUbr6F1hHriv8BmtzVQK1bmXXwo6b1jGlU0cmf8r");
		xhunter1_proc_handle_req handle_req = { 0 };
		handle_req.dwProcessId = dwProcessId;
		handle_req.dwDesiredAccess = dwDesiredAccess;

		xhunter1_req* req_packet = build_xhunter1_packet(785, (char*)&handle_req, sizeof(xhunter1_proc_handle_req));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		HANDLE hProc = INVALID_HANDLE_VALUE;

		if (res_packet != NULL) {
			if (res_packet->dwStatus == STATUS_SUCCESS) {
				hProc = res_packet->hProc;
			} else {
				SetLastError(res_packet->dwStatus);
			}

			free(res_packet);
		}

		VMP_END();
		return hProc;
	}

	VOID StartHandleHook(HANDLE hDriver) noexcept {
		VMP_BEGIN_MUTATION("dWEs7DNFCvPRajf4np3hy0gTsXKzNk2FNy9SQJYcMBXLICUEJcR2JZKn7lsVR7Ko");
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 1;

		xhunter1_req* req_packet = build_xhunter1_packet(782, (char*)&hookstate_req, sizeof(xhunter1_proc_sethookstate));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		free(res_packet);
		VMP_END();
	}

	VOID StopHandleHook(HANDLE hDriver) noexcept {
		VMP_BEGIN_MUTATION("1xqJaNfjOV4JGndjNjiejC4UJYxquAJpdjiWOi37qqCCEQz3le3jRs5ZJB2kObe3");
		xhunter1_proc_sethookstate hookstate_req = { 0 };
		hookstate_req.byHookState = 0;

		xhunter1_req* req_packet = build_xhunter1_packet(782, (char*)&hookstate_req, sizeof(xhunter1_proc_sethookstate));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		free(res_packet);
		VMP_END();
	}

	VOID RegisterPid(HANDLE hDriver, DWORD dwPid, ULONG dwFlag) noexcept {
		VMP_BEGIN_MUTATION("4RvApJPF9ibU59y7PkfHTlzroi29GBsb8Wi10M4f5ef9Bk8rYNvFX64L97PTMvou");

		PIDMAP_PARAM pidmap_req = { 0 };
		pidmap_req.pid = dwPid;
		pidmap_req.type = dwFlag;

		xhunter1_req* req_packet = build_xhunter1_packet(775, (char*)&pidmap_req, sizeof(PIDMAP_PARAM));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		free(res_packet);

		VMP_END();
	}

	VOID UnregisterPid(HANDLE hDriver, DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION("ItdSaN4rdgD2Pb1bRW1FV733AFz2z0c6V1MqURBSiaASSjBdGRVyfzl8BKchYuSu");
		PIDREMOVE_PARAM pidremove_req = { 0 };
		pidremove_req.pid = dwPid;

		xhunter1_req* req_packet = build_xhunter1_packet(779, (char*)&pidremove_req, sizeof(PIDREMOVE_PARAM));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		free(res_packet);
		VMP_END();
	}

	DWORD GetProtectedProcessFlag(HANDLE hDriver, DWORD dwPid) noexcept {
		VMP_BEGIN_MUTATION("UtDiWdNwqt3d741rBBZwyaN951nE9K8j1gKMMoU84MTQ6vWK2dpNfO9jzUsIiEeJ");
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = dwPid;

		xhunter1_req* req_packet = build_xhunter1_packet(797, (char*)&protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		DWORD dwFlag = 0;

		if (res_packet != NULL) {
			if (res_packet->dwStatus == STATUS_SUCCESS) {
				dwFlag = res_packet->dwProtectFlag;
			} else {
				SetLastError(res_packet->dwStatus);
			}

			free(res_packet);
		}

		VMP_END();
		return dwFlag;
	}

	VOID XRegisterReportReader(HANDLE hDriver) noexcept {
		VMP_BEGIN_MUTATION("zPfYNEXt171cm2LtZKGKVQ6o1K2ttAEiSTfJe0uDIDg95z24vGAWm2Vb2V1zUA8B");
		//dummy var, xhunter not read it
		xhunter1_proc_GetProcessProtectFlag_req protect_req = { 0 };
		protect_req.pid = 0;

		xhunter1_req* req_packet = build_xhunter1_packet(777, (char*)&protect_req, sizeof(xhunter1_proc_GetProcessProtectFlag_req));
		xhunter1_common_res* res_packet = send_xhunter1_packet(hDriver, req_packet);

		if (res_packet != NULL) free(res_packet);
		VMP_END();
	}
}