#ifdef _UNICODE
#undef UNICODE
#endif

#pragma comment(lib, "Dbghelp.lib")

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

constexpr size_t REMOTE_PE_HEADER_ALLOC_SIZE = 4096;
constexpr size_t REMOTE_RELOC_STUB_ALLOC_SIZE = 4096;

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

typedef struct {
    void* const remoteDllBaseAddress;
    LoadLibraryAPtr remoteLoadLibraryAAddress;
    GetProcAddressPtr remoteGetProcAddressAddress;
} RelocationStubParameters;

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {

    return reinterpret_cast<DWORD_PTR>(baseAddress) -
        reinterpret_cast<DWORD_PTR>(offset);
}

#define RvaToPointer(type, baseAddress, offset) \
    reinterpret_cast<type>( \
        reinterpret_cast<DWORD_PTR>(baseAddress) + offset)


#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

void* WriteDllFileBytesToProcess(HANDLE processHandle, const std::vector<char>& fileBytes)
{
    // Get the DOS and NT headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(&fileBytes[0]);
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(&fileBytes[dosHeader->e_lfanew]);

    // Reserve and commit memory in the process
    LPVOID remoteBaseAddress = VirtualAllocEx(processHandle, NULL,
        ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (remoteBaseAddress == NULL) {
        PrintErrorAndExit("VirtualAllocEx failed");
    }

    // Write each section to the process
    PIMAGE_SECTION_HEADER currentSection = IMAGE_FIRST_SECTION(ntHeader);
    for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {

        SIZE_T bytesWritten = 0;
        BOOL result = WriteProcessMemory(processHandle,
            (LPVOID)((DWORD_PTR)remoteBaseAddress + currentSection->VirtualAddress),
            &fileBytes[currentSection->PointerToRawData],
            currentSection->SizeOfRawData, &bytesWritten);
        if (result == 0 || bytesWritten == 0) {
            PrintErrorAndExit("WriteProcessMemory failed");
        }

        currentSection++;
    }

    // Write the PE header to the process
    SIZE_T bytesWritten = 0;
    BOOL result = WriteProcessMemory(processHandle, remoteBaseAddress,
        &fileBytes[0], REMOTE_PE_HEADER_ALLOC_SIZE, &bytesWritten);
    if (result == 0 || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory failed");
    }

    return remoteBaseAddress;
}
// Function to get remote module function address
LPVOID GetRemoteModuleFunctionAddress(const std::string& moduleName, const std::string& functionName, DWORD processId)
{
    // Get the local module base address
    HMODULE localModuleBaseAddress = GetModuleHandleA(moduleName.c_str());
    if (localModuleBaseAddress == NULL) {
        localModuleBaseAddress = LoadLibraryA(moduleName.c_str());
        if (localModuleBaseAddress == NULL) {
            PrintErrorAndExit("LoadLibraryA failed");
        }
    }

    // Get the local function address
    FARPROC localFunctionAddress = GetProcAddress(localModuleBaseAddress, functionName.c_str());
    if (localFunctionAddress == NULL) {
        PrintErrorAndExit("GetProcAddress failed");
    }

    // Calculate the function offset
    DWORD functionOffset = PointerToRva(localFunctionAddress, localModuleBaseAddress);

    // Create a snapshot of the modules in the process
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        PrintErrorAndExit("CreateToolhelp32Snapshot failed");
    }

    // Iterate through the modules in the snapshot
    MODULEENTRY32 module;
    module.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(snapshotHandle, &module)) {
        PrintErrorAndExit("Module32First failed");
    }

    do {
        std::string currentModuleName(module.szModule);
        std::transform(currentModuleName.begin(), currentModuleName.end(), currentModuleName.begin(),
            [](unsigned char letter) { return std::tolower(letter); });

        if (currentModuleName == moduleName) {
            return (LPVOID)((DWORD_PTR)module.modBaseAddr + functionOffset);
        }

    } while (Module32Next(snapshotHandle, &module));

    // No matching module found
    return NULL;
}
void RelocationStub(RelocationStubParameters* parameters) {

    const auto dosHeader{ reinterpret_cast<IMAGE_DOS_HEADER*>(
        parameters->remoteDllBaseAddress) };
    const auto ntHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<DWORD_PTR>(
            parameters->remoteDllBaseAddress) + dosHeader->e_lfanew) };

    const auto relocationOffset{ reinterpret_cast<DWORD_PTR>(
        parameters->remoteDllBaseAddress) - ntHeader->OptionalHeader.ImageBase };

    typedef struct {
        WORD offset : 12;
        WORD type : 4;
    } RELOCATION_INFO;

    const auto* baseRelocationDirectoryEntry{
        reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) };

    while (baseRelocationDirectoryEntry->VirtualAddress != 0) {

        const auto relocationCount{ 
            (baseRelocationDirectoryEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(RELOCATION_INFO) };

        const auto* baseRelocationInfo{ reinterpret_cast<RELOCATION_INFO*>(
            reinterpret_cast<DWORD_PTR>(baseRelocationDirectoryEntry) + sizeof(RELOCATION_INFO)) };

        for (size_t i{}; i < relocationCount; i++, baseRelocationInfo++) {
            if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64) {
                const auto relocFixAddress{ reinterpret_cast<DWORD*>(
                    reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
                    baseRelocationDirectoryEntry->VirtualAddress + baseRelocationInfo->offset) };
                *relocFixAddress += static_cast<DWORD>(relocationOffset);
            }
        }

        baseRelocationDirectoryEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<DWORD_PTR>(baseRelocationDirectoryEntry) +
            baseRelocationDirectoryEntry->SizeOfBlock);
    }

    const auto* const baseImportsDirectory{
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) };

    for (size_t index{}; baseImportsDirectory[index].Characteristics != 0; index++) {

        const auto* const moduleName{ RvaToPointer(char*, parameters->remoteDllBaseAddress,
            baseImportsDirectory[index].Name) };
        const auto loadedModuleHandle{ parameters->remoteLoadLibraryAAddress(moduleName) };

        auto* addressTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
            parameters->remoteDllBaseAddress, baseImportsDirectory[index].FirstThunk) };
        const auto* nameTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
            parameters->remoteDllBaseAddress, baseImportsDirectory[index].OriginalFirstThunk) };

        if (nameTableEntry == nullptr) {
            nameTableEntry = addressTableEntry;
        }

        for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {

            const auto* const importedFunction{ RvaToPointer(IMAGE_IMPORT_BY_NAME*,
                parameters->remoteDllBaseAddress, nameTableEntry->u1.AddressOfData) };

            if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

                addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
                    parameters->remoteGetProcAddressAddress(loadedModuleHandle,
                    MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
            }
            else {
                addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
                    parameters->remoteGetProcAddressAddress(loadedModuleHandle,
                    importedFunction->Name));
            }   
        }
    }

    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
        const auto* const baseTlsEntries{
            reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
                reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
                ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };

        const auto* tlsCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
            baseTlsEntries->AddressOfCallBacks) };
        while (tlsCallback != nullptr) {
            (*tlsCallback)(parameters->remoteDllBaseAddress, DLL_PROCESS_ATTACH,
                nullptr);
            tlsCallback++;
        }
    }

    using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

    const auto DllMain{ reinterpret_cast<DllMainPtr>(
        reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
        ntHeader->OptionalHeader.AddressOfEntryPoint) };

    DllMain(reinterpret_cast<HINSTANCE>(parameters->remoteDllBaseAddress),
        DLL_PROCESS_ATTACH, nullptr);
}

std::pair<void*, void*> WriteRelocationStubToTargetProcess(const HANDLE processHandle,
    const RelocationStubParameters& parameters) {

    auto* const remoteParametersAddress{ VirtualAllocEx(processHandle, nullptr,
        REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
    if (remoteParametersAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    SIZE_T bytesWritten{};
    auto result{ WriteProcessMemory(processHandle, remoteParametersAddress,
        &parameters, sizeof(RelocationStubParameters),
        &bytesWritten) };
    if (!result || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    auto* const remoteRelocationStubAddress{ VirtualAllocEx(processHandle, nullptr,
        REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    if (remoteRelocationStubAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    result = WriteProcessMemory(processHandle, remoteRelocationStubAddress, RelocationStub,
        REMOTE_RELOC_STUB_ALLOC_SIZE, &bytesWritten);
    if (!result || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    return std::make_pair(remoteRelocationStubAddress, remoteParametersAddress);
}

bool IsDllFile(const std::vector<char>& fileBytes) {
    if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }
    // Get the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)&fileBytes[0];
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    // Get the NT header
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)&fileBytes[dosHeader->e_lfanew];
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    // Check the magic number
    return ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC;
}

// Function to inject by manual mapping
void InjectByManualMapping(HANDLE processHandle, DWORD processId, const std::vector<char>& fileBytes)
{
    // Write the DLL file bytes to the process
    LPVOID remoteDllBaseAddress = WriteDllFileBytesToProcess(processHandle, fileBytes);

    // Get the addresses of the LoadLibraryA and GetProcAddress functions in the process
    LPVOID remoteLoadLibraryAddress = GetRemoteModuleFunctionAddress("kernel32.dll", "LoadLibraryA", processId);
    LPVOID remoteGetProcAddressAddress = GetRemoteModuleFunctionAddress("kernel32.dll", "GetProcAddress", processId);

    // Set up the parameters for the relocation stub
    RelocationStubParameters parameters(
        remoteDllBaseAddress,
        (LoadLibraryAPtr)(remoteLoadLibraryAddress),
        (GetProcAddressPtr)(remoteGetProcAddressAddress)
    );

    // Write the relocation stub to the target process
    std::pair<LPVOID, LPVOID> relocationInfo = WriteRelocationStubToTargetProcess(processHandle, parameters);

    // Print the start address and parameters address
    std::cout << "Start address: " << relocationInfo.first << "\n"
        << "Parameters address: " << relocationInfo.second << "\n";

    // Create a remote thread in the target process
    HANDLE remoteThread = CreateRemoteThreadEx(processHandle, NULL, 0,
        (LPTHREAD_START_ROUTINE)relocationInfo.first,
        relocationInfo.second, 0, NULL, NULL);
    if (remoteThread == NULL) {
        PrintErrorAndExit("CreateRemoteThreadEx failed");
    }
}

/*
int main(int argc, char* argv[]) {

    const auto fullModulePath{ GetInjectedDllPath("GenericDll.dll") };

    const auto processId{ GetTargetProcessAndThreadId(
        "Untitled - Notepad").first };

    InjectByManualMapping(processId, fullModulePath);

    return 0;
}
*/
