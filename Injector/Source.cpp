#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"
#include <string>


HANDLE findProcess(WCHAR* processName);
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);
void printError(const char* msg);


int main(int argc, char *argv[]) {

	const char* dllPath = argv[2];

	printf("Victim process name	: %s\n", argv[1]);
	printf("DLL to inject		: %s\n", argv[2]);
	printf("dllPath is %s\n", dllPath);

	STARTUPINFO info = { sizeof(info) };

	PROCESS_INFORMATION processInfo;

	std::string arguments = argv[1];

	if (argc >= 3) {
		for (int i = 3; i < argc; i++) {
			arguments += " ";
			arguments += argv[i];
		}
	}

	if (!CreateProcess(NULL, (char*) arguments.c_str(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &info, &processInfo)) {
		printf("Could not create process");
		return 1;
	}


	printf("Target process id - %d\n", processInfo.dwProcessId);

	HANDLE hProcess = processInfo.hProcess;

	if (hProcess != NULL) {
		BOOL injectSuccessful = loadRemoteDLL(hProcess, dllPath);
		if (injectSuccessful) {
			printf("[+] DLL1 injection successful! \n");
			getchar();
		} else {
			printf("[---] DLL1 injection failed. \n");
			getchar();
		}

	}

	CloseHandle(hProcess);
	printf("Resuming target...\n");
	ResumeThread(processInfo.hThread);
}


HANDLE findProcess(WCHAR* processName) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[---] Could not create snapshot.\n");
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		printError("Process32First");
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do {
		wchar_t temp[500];
		swprintf_s(temp, L"%hs", pe32.szExeFile);
		if (!wcscmp(temp, processName)) {
			wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			} else {
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				return NULL;

			}
		}

	} while (Process32Next(hProcessSnap, &pe32));

	printf("[---] %s has not been loaded into memory, aborting.\n", processName);
	return NULL;
}


BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) {
	printf("Enter any key to attempt DLL injection.");
	getchar();


	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
		}
	}

	return TRUE;
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