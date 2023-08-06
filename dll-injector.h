#ifndef INJECTBYMANUALMAPPING_H
#define INJECTBYMANUALMAPPING_H

#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#include <algorithm>
#include <format>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

# pragma once

constexpr size_t REMOTE_PE_HEADER_ALLOC_SIZE = 4096;
constexpr size_t REMOTE_RELOC_STUB_ALLOC_SIZE = 4096;

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

typedef struct {
    void* const remoteDllBaseAddress;
    LoadLibraryAPtr remoteLoadLibraryAAddress;
    GetProcAddressPtr remoteGetProcAddressAddress;
} RelocationStubParameters;

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset);

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line);

void* WriteDllFileBytesToProcess(HANDLE processHandle, const std::vector<char>& fileBytes);

LPVOID GetRemoteModuleFunctionAddress(const std::string& moduleName, const std::string& functionName, DWORD processId);

void RelocationStub(RelocationStubParameters* parameters);

std::pair<void*, void*> WriteRelocationStubToTargetProcess(const HANDLE processHandle, const RelocationStubParameters& parameters);

bool IsDllFile(const std::vector<char>& fileBytes);

void InjectByManualMapping(HANDLE hProc, DWORD processId, const std::vector<char>& fileBytes);

#endif // INJECTBYMANUALMAPPING_H

