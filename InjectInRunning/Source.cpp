#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"
#include <string>

void suspend(DWORD processId);
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);
void resume(DWORD processId);
void suspend(DWORD processId);
void printError(const char* msg);

int main(int argc, char *argv[]) {
	
	const char* dllPath = argv[2];
	const int processId = atoi(argv[1]);

	printf("Victim process id	: %s\n", argv[1]);
	printf("DLL to inject		: %s\n", argv[2]);
	printf("dllPath is %s\n", dllPath);

	PROCESS_INFORMATION processInfo;

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	suspend(processId);

	BOOL injectSuccessful = loadRemoteDLL(process, dllPath);
	if (injectSuccessful) {
		printf("[+] DLL injection successful! \n");
		getchar();
	} else {
		printf("[---] DLL injection failed. \n");
		getchar();
	}

	printf("Hit enter to resume process \n");
	getchar();
	resume(processId);
	printf("DONE!\n");
}

typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);

void suspend(DWORD processId) {
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandle("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

/*
void suspend(DWORD processId) {
	printf("Suspending all threads...\n");

	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do {
		if (threadEntry.th32OwnerProcessID == processId) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			int result = SuspendThread(hThread);
			if (result == -1) {
				printf("Error! Could not suspend thread %x\n", hThread);
			} else {
				printf("Thread %x suspended successfully, previous suspend count is %d\n", result);
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}
*/
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) {
	printf("Enter any key to attempt DLL injection.");
	getchar();


	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Dllpath is written at %x in the procces \n", dllPathAddressInRemoteMemory);
	if (dllPathAddressInRemoteMemory == NULL) {
		printf("[---] VirtualAllocEx unsuccessful.\n");
		printError(TEXT("VirtualAllocEx"));
		getchar();
		return FALSE;
	}

	BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

	if (!succeededWriting) {
		printf("[---] WriteProcessMemory unsuccessful.\n");
		printError(TEXT("WriteProcessMemory"));
		getchar();
		return FALSE;
	} else {

		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (loadLibraryAddress == NULL) {
			printf("[---] LoadLibrary not found in process.\n");
			printError(TEXT("GetProcAddress"));
			getchar();
			return FALSE;
		} else {
			HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
			if (remoteThread == NULL) {
				printf("[---] CreateRemoteThread unsuccessful.\n");
				printError(TEXT("CreateRemoteThread"));
				return FALSE;
			}
			const int remoteThreadId = GetThreadId(remoteThread);
			printf("Remote thred successfully created. Id - %d\n", remoteThreadId);
		}
	}

	return TRUE;
}

void resume(DWORD processId) {
	printf("Resuming all threads...\n");
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do {
		if (threadEntry.th32OwnerProcessID == processId) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			int result = ResumeThread(hThread);
			if (result == -1) {
				printf("Error! Could not resume thread %x\n", hThread);
			} else {
				printf("Thread %x resumed successfully, previous suspend count is %d\n", result);
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}


void printError(const char* msg) {
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg, 256, NULL);

	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	printf("[---] %s failed with error %d (%s) \n", msg, eNum, sysMsg);
}