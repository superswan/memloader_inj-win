#include <Windows.h>
#include <TlHelp32.h>

#pragma once

DWORD GetPidByName(const wchar_t* procname);
