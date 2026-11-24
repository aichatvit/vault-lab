#pragma once

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#define CDECL __cdecl
#else
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#define CDECL __attribute__((__cdecl__))
#endif // _WIN32