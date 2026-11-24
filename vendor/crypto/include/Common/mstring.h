#pragma once

#include <string>
#include <string_view>

#ifdef _WIN32
using mstring = std::wstring; //typedef std::wstring mstring;
using mchar = std::wstring::value_type;
using mstringView = std::wstring_view;
#define TOWSTRING1(x) L##x
#define mlit(x) TOWSTRING1(x)
#else
using mstring = std::string;
using mchar = std::string::value_type;
using mstringView = std::string_view;
#define mlit(x) x
//typedef std::string mstring;
#endif // _WIN32

//namespace LicensingConsole { namespace Common
//{
//#ifdef _WIN32
//	using mstring = std::wstring; //typedef std::wstring mstring;
//	using mchar = std::wstring::value_type;
//#define TOWSTRING1(x) L##x
//#define mlit(x) TOWSTRING1(x)
//#else
//	using mstring = std::string;
//	using mchar = std::string::value_type;
//#define mlit(x) x
//	//typedef std::string mstring;
//#endif // _WIN32
//}}
//
//
////template< typename CharT > constexpr CharT const* NarrowOrWide(char const*, wchar_t const*);
////template<> /*static*/ constexpr char const* NarrowOrWide< char >(char const* c, wchar_t const*)
////{
////	return c;
////};
////template<> /*static*/ constexpr wchar_t const* NarrowOrWide< wchar_t >(char const*, wchar_t const* w)
////{
////	return w;
////};
////
////#define TOWSTRING1(x) L##x
////#define TOWSTRING(x) TOWSTRING1(x)  
////#define NARROW_OR_WIDE( C, STR ) NarrowOrWide< C >( ( STR ), TOWSTRING( STR ) )
//}}
