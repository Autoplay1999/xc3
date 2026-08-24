#pragma once
#ifndef XC3_ERROR_HPP
#define XC3_ERROR_HPP

#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <format>
#include <source_location>
#include <expected>

namespace xc3 {

    inline std::string NTStatusToString(NTSTATUS status) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
            GetModuleHandleA("ntdll.dll"),
            status,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer,
            0,
            nullptr);

        if (!size || !messageBuffer) {
            return std::format("Unknown NTSTATUS (0x{:08X})", static_cast<uint32_t>(status));
        }

        std::string result(messageBuffer, size);
        LocalFree(messageBuffer);
        
        // Remove trailing \r\n
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
            result.pop_back();
        }
        
        return result;
    }

    class Error {
    public:
        Error(NTSTATUS status, std::string message, std::source_location loc = std::source_location::current())
            : m_status(status), m_message(std::move(message)), m_loc(loc) {}

        Error(std::string message, std::source_location loc = std::source_location::current())
            : m_status(STATUS_UNSUCCESSFUL), m_message(std::move(message)), m_loc(loc) {}

        NTSTATUS status() const noexcept { return m_status; }
        const std::string& message() const noexcept { return m_message; }
        const std::source_location& location() const noexcept { return m_loc; }

        std::string formatted() const {
            return std::format("[{}:{}] {} - NTSTATUS 0x{:08X} ({})", 
                m_loc.file_name(), 
                m_loc.line(), 
                m_message, 
                static_cast<uint32_t>(m_status),
                NTStatusToString(m_status));
        }

    private:
        NTSTATUS m_status;
        std::string m_message;
        std::source_location m_loc;
    };

    template<typename T>
    class Result : public std::expected<T, Error> {
    public:
        using std::expected<T, Error>::expected;

        // Modern convenience
        bool is_success() const noexcept { return this->has_value(); }

        // Quick access to error status
        NTSTATUS status() const noexcept { 
            return this->has_value() ? STATUS_SUCCESS : this->error().status(); 
        }

        // Implicit conversion to bool for simple checks
        explicit operator bool() const noexcept { return this->has_value(); }
    };
}

#define X_FAIL(status, msg) return std::unexpected(xc3::Error(status, msg))
#define X_FAIL_MSG(msg) return std::unexpected(xc3::Error(msg))

#define X_BAIL_IF(cond, status, msg) \
    if ((cond)) { return std::unexpected(xc3::Error(status, msg)); }

#endif
