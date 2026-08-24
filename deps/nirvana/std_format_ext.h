#pragma once
#ifndef STD_FORMAT_EXT_H
#define STD_FORMAT_EXT_H
#include <format>

_STD_BEGIN
_FMT_P2286_BEGIN

_EXPORT_STD template <class... _Types>
_NODISCARD string format_(string_view _Fmt, _Types&&... _Args) {
    return _STD vformat(_Fmt, _STD make_format_args(_Args...));
}

_EXPORT_STD template <class... _Types>
_NODISCARD wstring format_(wstring_view _Fmt, _Types&&... _Args) {
    return _STD vformat(_Fmt, _STD make_wformat_args(_Args...));
}

_FMT_P2286_END
_STD_END

#endif // STD_FORMAT_EXT_H