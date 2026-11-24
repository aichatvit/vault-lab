#pragma once

#include <string>
#include "mstring.h"
#include <iconv.h>
#include <type_traits>
#include <clocale>
#include <locale>

namespace Common
{
    class mStringHelper_Linux;
    using mStringHelper = mStringHelper_Linux;

    class mStringHelper_Linux
    {
    public:
        static long int mstrToLongInt(const mchar* str, mchar** endptr, int base)
        {
            return strtol(str, endptr, base);
        }
        static void stringToMString_NoLenCalc(const char* str, size_t lenOfStr, mchar* mStr_out, size_t lenOfMStr)
        {
            if (str == mStr_out)
                return;
            std::copy_n(str, lenOfStr, mStr_out);
        }
        static size_t getLenInMChar(const char* str, size_t lenOfStr)
        {
            return lenOfStr;
        }
        static std::wstring mstringToWString(const mstringView& mstr)
        {
            static_assert(std::is_same_v<char, mchar>);

            const std::locale l("");
            const auto name_locale = l.name();
            const auto pos_dot = name_locale.find_last_of('.');
            const auto encoding = name_locale.substr(pos_dot + 1);

            std::vector<char> mstrAsVec(mstr.size() + 1, mlit('\0'));
            mstr.copy(mstrAsVec.data(), mstr.size(), 0);
            mchar* pIn = mstrAsVec.data();
            constexpr size_t sizeOFWchar = sizeof(wchar_t);
            std::vector<wchar_t> strAsVec(mstrAsVec.size() * sizeOFWchar, mlit('\0'));
            char* pOut = reinterpret_cast<char*>(strAsVec.data());
            size_t srclen = mstr.size();
            size_t dstlen = strAsVec.size();

            iconv_t conv = iconv_open("WCHAR_T", encoding.data());
            iconv(conv, &pIn, &srclen, &pOut, &dstlen);
            iconv_close(conv);

            return std::wstring{ strAsVec.data() };
        }
        /*static std::wstring mstringToWString(const mstring& mstr)
        {
            static_assert(std::is_same_v<char, mchar>);

            const std::locale l("");
            const auto name_locale = l.name();
            const auto pos_dot = name_locale.find_last_of('.');
            const auto encoding = name_locale.substr(pos_dot + 1);

            std::vector<char> mstrAsVec(mstr.size() + 1, mlit('\0'));
            mstr.copy(mstrAsVec.data(), mstr.size(), 0);
            mchar* pIn = mstrAsVec.data();
            constexpr size_t sizeOFWchar = sizeof(wchar_t);
            std::vector<wchar_t> strAsVec(mstrAsVec.size() * sizeOFWchar, mlit('\0'));
            char* pOut = reinterpret_cast<char*>(strAsVec.data());
            size_t srclen = mstr.size();
            size_t dstlen = strAsVec.size();

            iconv_t conv = iconv_open("WCHAR_T", encoding.data());
            iconv(conv, &pIn, &srclen, &pOut, &dstlen);
            iconv_close(conv);

            return std::wstring{ strAsVec.data() };
        }*/
        static mstring stringToMString(const std::string& str)
        {
            return mstring(str);
        }
    };
}
