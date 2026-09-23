#include <phnt_windows.h>
#include <phnt.h>

#include <iostream>
#include <cassert>
#include <filesystem>
#include <string>

#include "../src/xc3_api/xc3api.h"
#include "../src/xc3_api/util.hpp"

int main()
{
    const std::wstring svcName = L"nirvana";
    const std::filesystem::path driverPath = "%windir%\\nirvana.sys";

    // Ensure service is stopped initially
    util::stop_service_entry(svcName);
    std::cout << "[+] Initial state: ensuring nirvana is stopped." << std::endl;

    // Test Case 1: Stopped service + exportDriver = false
    // Should start the service, attach, and stop it on disconnect
    {
        xc3api::XC3Client client;
        bool connected = client.Connect(driverPath, false);
        if (!connected) {
            std::cerr << "[-] Test Case 1 Connect failed, error: " << client.GetLastError() << std::endl;
            return 1;
        }
        std::cout << "[+] Test Case 1: Connect succeeded while service was stopped." << std::endl;

        if (!client.IsRunning()) {
            std::cerr << "[-] Expected service to be running." << std::endl;
            return 1;
        }
        std::cout << "[+] Test Case 1: Service is confirmed running." << std::endl;
    } // client destructs here -> Disconnect()

    if (util::is_service_running(svcName)) {
        std::cerr << "[-] Test Case 1 failed: Service was NOT stopped on exit!" << std::endl;
        util::stop_service_entry(svcName);
        return 1;
    }
    std::cout << "[+] Test Case 1 SUCCESS: Service was cleanly stopped on disconnect." << std::endl;

    // Test Case 2: Already running service + exportDriver = false
    // Should attach, and NOT stop the service on disconnect
    {
        if (!util::start_service_entry(svcName)) {
            std::cerr << "[-] Failed to manually start service for Test Case 2." << std::endl;
            return 1;
        }
        std::cout << "[+] Pre-condition: nirvana is manually started and running." << std::endl;

        {
            xc3api::XC3Client client;
            bool connected = client.Connect(driverPath, false);
            if (!connected) {
                std::cerr << "[-] Test Case 2 Connect failed, error: " << client.GetLastError() << std::endl;
                util::stop_service_entry(svcName);
                return 1;
            }
            std::cout << "[+] Test Case 2: Connect succeeded on already-running service." << std::endl;
        } // client destructs here -> Disconnect()

        if (!util::is_service_running(svcName)) {
            std::cerr << "[-] Test Case 2 failed: Service was stopped on exit, but should have been kept running!" << std::endl;
            return 1;
        }
        std::cout << "[+] Test Case 2 SUCCESS: Service is STILL running after disconnect." << std::endl;

        // Clean up
        util::stop_service_entry(svcName);
        std::cout << "[+] Cleaned up service after Test Case 2." << std::endl;
    }

    std::cout << "\n[=== ALL LIFECYCLE TESTS PASSED ===]\n" << std::endl;
    return 0;
}
