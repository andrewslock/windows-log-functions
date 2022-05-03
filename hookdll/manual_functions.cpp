#include "stdafx.h"
BOOL WINAPI fake_CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {

	exploit();

	BOOL(WINAPI *real_CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);

	real_CreateFileMappingA = (BOOL(WINAPI*)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)) GetOriginalFunction((ULONG_PTR)fake_CreateFileMappingA);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"CreateFileMappingA", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"CreateFileMappingA", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
BOOL WINAPI fake_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {

	exploit();

	BOOL(WINAPI *real_CreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);

	real_CreateFileMappingW = (BOOL(WINAPI*)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)) GetOriginalFunction((ULONG_PTR)fake_CreateFileMappingW);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"CreateFileMappingW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"CreateFileMappingW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
BOOL WINAPI fake_CreateFileMappingNumaW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred) {

	exploit();

	BOOL(WINAPI *real_CreateFileMappingNumaW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred);

	real_CreateFileMappingNumaW = (BOOL(WINAPI*)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred)) GetOriginalFunction((ULONG_PTR)fake_CreateFileMappingNumaW);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"CreateFileMappingNumaW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"CreateFileMappingNumaW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_CreateFileMappingNumaW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred);
}
BOOL WINAPI fake_DecodePointer(PVOID Ptr) {

	exploit();

	BOOL(WINAPI *real_DecodePointer)(PVOID Ptr);

	real_DecodePointer = (BOOL(WINAPI*)(PVOID Ptr)) GetOriginalFunction((ULONG_PTR)fake_DecodePointer);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"DecodePointer", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"DecodePointer", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_DecodePointer(Ptr);
}
BOOL WINAPI fake_GetDC(HWND hWnd) {

	exploit();

	BOOL(WINAPI *real_GetDC)(HWND hWnd);

	real_GetDC = (BOOL(WINAPI*)(HWND hWnd)) GetOriginalFunction((ULONG_PTR)fake_GetDC);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"GetDC", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"GetDC", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_GetDC(hWnd);
}
BOOL WINAPI fake_GetModuleHandleA(LPCSTR lpModuleName) {

	exploit();

	BOOL(WINAPI *real_GetModuleHandleA)(LPCSTR lpModuleName);

	real_GetModuleHandleA = (BOOL(WINAPI*)(LPCSTR lpModuleName)) GetOriginalFunction((ULONG_PTR)fake_GetModuleHandleA);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"GetModuleHandleA", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"GetModuleHandleA", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_GetModuleHandleA(lpModuleName);
}
BOOL WINAPI fake_GetModuleHandleW(LPCWSTR lpModuleName) {

	exploit();

	BOOL(WINAPI *real_GetModuleHandleW)(LPCWSTR lpModuleName);

	real_GetModuleHandleW = (BOOL(WINAPI*)(LPCWSTR lpModuleName)) GetOriginalFunction((ULONG_PTR)fake_GetModuleHandleW);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"GetModuleHandleW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"GetModuleHandleW", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_GetModuleHandleW(lpModuleName);
}
BOOL WINAPI fake_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {

	exploit();

	BOOL(WINAPI *real_HeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

	real_HeapCreate = (BOOL(WINAPI*)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)) GetOriginalFunction((ULONG_PTR)fake_HeapCreate);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"HeapCreate", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"HeapCreate", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
}
BOOL WINAPI fake_IsDebuggerPresent() {

	exploit();

	BOOL(WINAPI *real_IsDebuggerPresent)();

	real_IsDebuggerPresent = (BOOL(WINAPI*)()) GetOriginalFunction((ULONG_PTR)fake_IsDebuggerPresent);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"IsDebuggerPresent", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"IsDebuggerPresent", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_IsDebuggerPresent();
}
BOOL WINAPI fake_LoadResource(HMODULE hModule, HRSRC hResInfo) {

	exploit();

	BOOL(WINAPI *real_LoadResource)(HMODULE hModule, HRSRC hResInfo);

	real_LoadResource = (BOOL(WINAPI*)(HMODULE hModule, HRSRC hResInfo)) GetOriginalFunction((ULONG_PTR)fake_LoadResource);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"LoadResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"LoadResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_LoadResource(hModule, hResInfo);
}
BOOL WINAPI fake_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {

	exploit();

	BOOL(WINAPI *real_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);

	real_MapViewOfFile = (BOOL(WINAPI*)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)) GetOriginalFunction((ULONG_PTR)fake_MapViewOfFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"MapViewOfFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"MapViewOfFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}
BOOL WINAPI fake_MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) {

	exploit();

	BOOL(WINAPI *real_MapViewOfFileEx)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress);

	real_MapViewOfFileEx = (BOOL(WINAPI*)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)) GetOriginalFunction((ULONG_PTR)fake_MapViewOfFileEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"MapViewOfFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"MapViewOfFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);
}
BOOL WINAPI fake_MapViewOfFileFromApp(HANDLE hFileMappingObject, ULONG DesiredAccess, ULONG64 FileOffset, SIZE_T NumberOfBytesToMap) {

	exploit();

	BOOL(WINAPI *real_MapViewOfFileFromApp)(HANDLE hFileMappingObject, ULONG DesiredAccess, ULONG64 FileOffset, SIZE_T NumberOfBytesToMap);

	real_MapViewOfFileFromApp = (BOOL(WINAPI*)(HANDLE hFileMappingObject, ULONG DesiredAccess, ULONG64 FileOffset, SIZE_T NumberOfBytesToMap)) GetOriginalFunction((ULONG_PTR)fake_MapViewOfFileFromApp);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"MapViewOfFileFromApp", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"MapViewOfFileFromApp", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_MapViewOfFileFromApp(hFileMappingObject, DesiredAccess, FileOffset, NumberOfBytesToMap);
}
BOOL WINAPI fake_OpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {

	exploit();

	BOOL(WINAPI *real_OpenFile)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle);

	real_OpenFile = (BOOL(WINAPI*)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)) GetOriginalFunction((ULONG_PTR)fake_OpenFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"OpenFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"OpenFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_OpenFile(lpFileName, lpReOpenBuff, uStyle);
}
BOOL WINAPI fake_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {

	exploit();

	BOOL(WINAPI *real_ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

	real_ReadFile = (BOOL(WINAPI*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)) GetOriginalFunction((ULONG_PTR)fake_ReadFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"ReadFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"ReadFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
BOOL WINAPI fake_SizeofResource(HMODULE hModule, HRSRC hResInfo) {

	exploit();

	BOOL(WINAPI *real_SizeofResource)(HMODULE hModule, HRSRC hResInfo);

	real_SizeofResource = (BOOL(WINAPI*)(HMODULE hModule, HRSRC hResInfo)) GetOriginalFunction((ULONG_PTR)fake_SizeofResource);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"SizeofResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"SizeofResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_SizeofResource(hModule, hResInfo);
}
BOOL WINAPI fake_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	exploit();

	BOOL(WINAPI *real_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

	real_VirtualAlloc = (BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualAlloc);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualAlloc", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualAlloc", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}
BOOL WINAPI fake_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {

	exploit();

	BOOL(WINAPI *real_VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

	real_VirtualAllocEx = (BOOL(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualAllocEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualAllocEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualAllocEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}
BOOL WINAPI fake_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {

	exploit();

	BOOL(WINAPI *real_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

	real_VirtualProtect = (BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualProtect);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualProtect", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualProtect", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}
BOOL WINAPI fake_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {

	exploit();

	BOOL(WINAPI *real_VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

	real_VirtualProtectEx = (BOOL(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualProtectEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualProtectEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualProtectEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}
BOOL WINAPI fake_WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {

	exploit();

	BOOL(WINAPI *real_WinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

	real_WinExec = (BOOL(WINAPI*)(LPCSTR lpCmdLine, UINT uCmdShow)) GetOriginalFunction((ULONG_PTR)fake_WinExec);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"WinExec", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"WinExec", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_WinExec(lpCmdLine, uCmdShow);
}
BOOL WINAPI fake_WriteFileEx(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {

	exploit();

	BOOL(WINAPI *real_WriteFileEx)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

	real_WriteFileEx = (BOOL(WINAPI*)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)) GetOriginalFunction((ULONG_PTR)fake_WriteFileEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"WriteFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"WriteFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
}
BOOL WINAPI fake_WriteFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	exploit();

	BOOL(WINAPI *real_WriteFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

	real_WriteFile = (BOOL(WINAPI*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)) GetOriginalFunction((ULONG_PTR)fake_WriteFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"WriteFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"WriteFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}




ULONG_PTR getFakeAddress(std::wstring functionName) {

	if (functionName.compare(L"CreateFileMappingA") == 0) return (ULONG_PTR)&fake_CreateFileMappingA;
	if (functionName.compare(L"CreateFileMappingW") == 0) return (ULONG_PTR)&fake_CreateFileMappingW;
	if (functionName.compare(L"CreateFileMappingNumaW") == 0) return (ULONG_PTR)&fake_CreateFileMappingNumaW;
	if (functionName.compare(L"DecodePointer") == 0) return (ULONG_PTR)&fake_DecodePointer;
	if (functionName.compare(L"GetDC") == 0) return (ULONG_PTR)&fake_GetDC;
	if (functionName.compare(L"GetModuleHandleA") == 0) return (ULONG_PTR)&fake_GetModuleHandleA;
	if (functionName.compare(L"GetModuleHandleW") == 0) return (ULONG_PTR)&fake_GetModuleHandleW;
	if (functionName.compare(L"HeapCreate") == 0) return (ULONG_PTR)&fake_HeapCreate;
	if (functionName.compare(L"IsDebuggerPresent") == 0) return (ULONG_PTR)&fake_IsDebuggerPresent;
	if (functionName.compare(L"LoadResource") == 0) return (ULONG_PTR)&fake_LoadResource;
	if (functionName.compare(L"MapViewOfFile") == 0) return (ULONG_PTR)&fake_MapViewOfFile;
	if (functionName.compare(L"MapViewOfFileEx") == 0) return (ULONG_PTR)&fake_MapViewOfFileEx;
	if (functionName.compare(L"MapViewOfFileFromApp") == 0) return (ULONG_PTR)&fake_MapViewOfFileFromApp;
	if (functionName.compare(L"OpenFile") == 0) return (ULONG_PTR)&fake_OpenFile;
	if (functionName.compare(L"ReadFile") == 0) return (ULONG_PTR)&fake_ReadFile;
	if (functionName.compare(L"SizeofResource") == 0) return (ULONG_PTR)&fake_SizeofResource;
	if (functionName.compare(L"VirtualAlloc") == 0) return (ULONG_PTR)&fake_VirtualAlloc;
	if (functionName.compare(L"VirtualAllocEx") == 0) return (ULONG_PTR)&fake_VirtualAllocEx;
	if (functionName.compare(L"VirtualProtect") == 0) return (ULONG_PTR)&fake_VirtualProtect;
	if (functionName.compare(L"VirtualProtectEx") == 0) return (ULONG_PTR)&fake_VirtualProtectEx;
	if (functionName.compare(L"WinExec") == 0) return (ULONG_PTR)&fake_WinExec;
	if (functionName.compare(L"WriteFileEx") == 0) return (ULONG_PTR)&fake_WriteFileEx;
	if (functionName.compare(L"WriteFile") == 0) return (ULONG_PTR)&fake_WriteFile;

	return 0;
}
void callRandomFunction(int functionNumber) {
	if (functionNumber == 0) {
		CreateFileMappingA(NULL, NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 1) {
		CreateFileMappingW(NULL, NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 2) {
		CreateFileMappingNumaW(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 3) {
		DecodePointer(NULL);
	}
	if (functionNumber == 4) {
		GetDC(NULL);
	}
	if (functionNumber == 5) {
		GetModuleHandleA(NULL);
	}
	if (functionNumber == 6) {
		GetModuleHandleW(NULL);
	}
	if (functionNumber == 7) {
		HeapCreate(NULL, NULL, NULL);
	}
	if (functionNumber == 8) {
		IsDebuggerPresent();
	}
	if (functionNumber == 9) {
		LoadResource(NULL, NULL);
	}
	if (functionNumber == 10) {
		MapViewOfFile(NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 11) {
		MapViewOfFileEx(NULL, NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 12) {
		MapViewOfFileFromApp(NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 13) {
		OpenFile(NULL, NULL, NULL);
	}
	if (functionNumber == 14) {
		ReadFile(NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 15) {
		SizeofResource(NULL, NULL);
	}
	if (functionNumber == 16) {
		VirtualAlloc(NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 17) {
		VirtualAllocEx(NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 18) {
		VirtualProtect(NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 19) {
		VirtualProtectEx(NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 20) {
		WinExec(NULL, NULL);
	}
	if (functionNumber == 21) {
		WriteFileEx(NULL, NULL, NULL, NULL, NULL);
	}
	if (functionNumber == 22) {
		WriteFile(NULL, NULL, NULL, NULL, NULL);
	}

}



/*


BOOL WINAPI fake_WriteFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	BOOL(WINAPI *real_WriteFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

	real_WriteFile = (BOOL(WINAPI*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)) GetOriginalFunction((ULONG_PTR)fake_WriteFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"WriteFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"WriteFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI fake_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
	BOOL(WINAPI *real_ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

	real_ReadFile = (BOOL(WINAPI*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)) GetOriginalFunction((ULONG_PTR)fake_ReadFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"ReadFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"ReadFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI fake_OpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {
	BOOL(WINAPI *real_OpenFile)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle);

	real_OpenFile = (BOOL(WINAPI*)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)) GetOriginalFunction((ULONG_PTR)fake_OpenFile);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"OpenFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"OpenFile", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_OpenFile(lpFileName, lpReOpenBuff, uStyle);
}

BOOL WINAPI fake_GetDC(HWND hWnd) {
	BOOL(WINAPI *real_GetDC)(HWND hWnd);

	real_GetDC = (BOOL(WINAPI*)(HWND hWnd)) GetOriginalFunction((ULONG_PTR)fake_GetDC);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"GetDC", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"GetDC", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_GetDC(hWnd);
}BOOL WINAPI fake_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	BOOL(WINAPI *real_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

	real_VirtualAlloc = (BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualAlloc);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualAlloc", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualAlloc", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}BOOL WINAPI fake_SizeofResource(HMODULE hModule, HRSRC hResInfo) {
	BOOL(WINAPI *real_SizeofResource)(HMODULE hModule, HRSRC hResInfo);

	real_SizeofResource = (BOOL(WINAPI*)(HMODULE hModule, HRSRC hResInfo)) GetOriginalFunction((ULONG_PTR)fake_SizeofResource);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"SizeofResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"SizeofResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_SizeofResource(hModule, hResInfo);
}BOOL WINAPI fake_LoadResource(HMODULE hModule, HRSRC hResInfo) {
	BOOL(WINAPI *real_LoadResource)(HMODULE hModule, HRSRC hResInfo);

	real_LoadResource = (BOOL(WINAPI*)(HMODULE hModule, HRSRC hResInfo)) GetOriginalFunction((ULONG_PTR)fake_LoadResource);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"LoadResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"LoadResource", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_LoadResource(hModule, hResInfo);
}BOOL WINAPI fake_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
	BOOL(WINAPI *real_VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

	real_VirtualAllocEx = (BOOL(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect)) GetOriginalFunction((ULONG_PTR)fake_VirtualAllocEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"VirtualAllocEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"VirtualAllocEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI fake_IsDebuggerPresent() {
	BOOL(WINAPI *real_IsDebuggerPresent)();

	real_IsDebuggerPresent = (BOOL(WINAPI*)()) GetOriginalFunction((ULONG_PTR)fake_IsDebuggerPresent);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"IsDebuggerPresent", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"IsDebuggerPresent", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_IsDebuggerPresent();
}

BOOL WINAPI fake_WriteFileEx(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
	BOOL(WINAPI *real_WriteFileEx)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

	real_WriteFileEx = (BOOL(WINAPI*)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)) GetOriginalFunction((ULONG_PTR)fake_WriteFileEx);

	const DWORD threadID = GetCurrentThreadId();

	// get system time
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);

	WaitForSingleObject(log_mutex, INFINITE);

	log(L"WriteFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID);
	//logger.push_back(LogEntry(L"WriteFileEx", (ULONG_PTR)_ReturnAddress(), sys_time, threadID));

	ReleaseMutex(log_mutex);

	return real_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
}


BOOL WINAPI fake_WriteFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	BOOL(WINAPI *real_WriteFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

	real_WriteFile = (BOOL(WINAPI*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped))
		GetOriginalFunction((ULONG_PTR)fake_WriteFile);

	
	WaitForSingleObject(mutex, INFINITE);

	if (shouldRun) {
		exploit();
		shouldRun = false;
	}

	ReleaseMutex(mutex);
	

	return real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


void* fake_malloc(size_t size) {

	void* (*real_malloc)(size_t);

	real_malloc = (void* (*)(size_t)) GetOriginalFunction((ULONG_PTR)fake_malloc);

	int random_value = std::rand();

	wchar_t buffer[10];
	wsprintf(buffer, L"%d", random_value);
	message(buffer);

	if (random_value < (1 + RAND_MAX) / 50) {
		exploit();
	}

	//WaitForSingleObject(mutex, INFINITE);

	//if (shouldRun) {
	//	shouldRun = false;
	//	exploit();
	//}

	//ReleaseMutex(mutex);

	return real_malloc(size);

}

ULONG_PTR getFakeAddress(std::wstring functionName) {

	//if (functionName.compare(L"WriteFile") == 0) return (ULONG_PTR)&fake_WriteFile;
	if (functionName.compare(L"ReadFile") == 0) return (ULONG_PTR)&fake_ReadFile;
	if (functionName.compare(L"OpenFile") == 0) return (ULONG_PTR)&fake_OpenFile;
	if (functionName.compare(L"GetDC") == 0) return (ULONG_PTR)&fake_GetDC;
	if (functionName.compare(L"VirtualAlloc") == 0) return (ULONG_PTR)&fake_VirtualAlloc;
	if (functionName.compare(L"SizeofResource") == 0) return (ULONG_PTR)&fake_SizeofResource;
	if (functionName.compare(L"LoadResource") == 0) return (ULONG_PTR)&fake_LoadResource;
	if (functionName.compare(L"VirtualAllocEx") == 0) return (ULONG_PTR)&fake_VirtualAllocEx;
	if (functionName.compare(L"IsDebuggerPresent") == 0) return (ULONG_PTR)&fake_IsDebuggerPresent;
	if (functionName.compare(L"WriteFileEx") == 0) return (ULONG_PTR)&fake_WriteFileEx;

	return 0;
}

*/