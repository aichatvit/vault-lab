#pragma once

#include <string>
#include "mstring.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <stdexcept>
//#include <alloca>

namespace Common
{
    class mStringHelper_Win;
    using mStringHelper = mStringHelper_Win;

    class mStringHelper_Win
    {
    public:
        static long int mstrToLongInt(const mchar* str, mchar** endptr, int base)
        {
            return wcstol(str, endptr, base);
        }
        static void stringToMString_NoLenCalc(const char* str, size_t lenOfStr, mchar* mStr_out, size_t lenOfMStr)
        {
            if (lenOfStr == 0)
                return;
            int charsConverted = MultiByteToWideChar(CP_ACP, 0,
                str, static_cast<int>(lenOfStr), mStr_out, static_cast<int>(lenOfMStr));
            if (charsConverted == 0)
                throw std::runtime_error("Failed converting UTF-8 string to UTF-16");
        }
        static size_t getLenInMChar(const char* str, size_t lenOfStr)
        {
            size_t charsNeeded = MultiByteToWideChar(CP_ACP, 0,
                str, static_cast<int>(lenOfStr), nullptr, 0);
            if (charsNeeded == 0)
                throw std::runtime_error("Failed converting UTF-8 string to UTF-16");
            return charsNeeded;
        }
        static std::wstring mstringToWString(const mstringView& mstr)
        {
            static_assert(std::is_same_v<mchar, wchar_t>);
            return std::wstring{ mstr };
        }
        /*static std::wstring mstringToWString(const mstring& mstr)
        {
            static_assert(std::is_same_v<mchar, wchar_t>);
            return std::wstring{ mstr };
        }*/
        static mstring stringToMString(const std::string& str)
        {
            if (str.empty())
                return mstring();

            size_t charsNeeded = MultiByteToWideChar(CP_ACP, 0,
                str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (charsNeeded == 0)
                throw std::runtime_error("Failed converting UTF-8 string to UTF-16");


            std::vector<wchar_t> buffer(charsNeeded);
            int charsConverted = MultiByteToWideChar(CP_ACP, 0,
                str.data(), static_cast<int>(str.size()), &buffer[0], 
                static_cast<int>(buffer.size()));
            if (charsConverted == 0)
                throw std::runtime_error("Failed converting UTF-8 string to UTF-16");

            return mstring(&buffer[0], charsConverted);
        }
    };
}