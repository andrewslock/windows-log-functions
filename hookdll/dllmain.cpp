#include "stdafx.h"


#include "manual_functions.h"

#include "generated_functions.h"
#include <algorithm>

////////////////////
#include "manual_functions.cpp"

/////////////////////
std::vector<FunctionData> data;

//extern "C" __declspec(noinline) ULONG_PTR getOriginalAddressByReturnAddress(const void* return_address);
/*
__declspec(noinline) ULONG_PTR getOriginalAddressByReturnAddress(const void* return_address) {

	
#ifdef _M_IX86 // if x86

	const BYTE const* returnAddress = (BYTE*) return_address;
	WORD command = *(((WORD*)return_address) - 3);
	
	// if command is ff15
	if (command == 0x15ff || command == 0x15cc) {
		ULONG_PTR addressWithAddress = *((ULONG_PTR*)(returnAddress - 4));
		ULONG_PTR address = *((ULONG_PTR*)addressWithAddress);
		return address;
	}


	command = *(((WORD*)return_address) - 1);
	// if command is ffd1 (call ecx)
	if (command == 0xd1ff || command == 0xd1cc) {
		BYTE* jmp = (BYTE*)ECX_REGISTRY;
		DWORD* jmpAddressPtr = (DWORD*)(jmp + 2);
		DWORD* jmpAddress = (DWORD*)(*jmpAddressPtr);
		return *jmpAddress;
	}


	command = *(((WORD*)return_address) - 1);
	// if command is ffd3 (call ebx)
	if (command == 0xd3ff || command == 0xd3cc) {
		ULONG_PTR address;
		__asm {
			mov address, ebx
		}
		return address;
	}



	command = *(((WORD*)return_address) - 1);
	// if command is ffd7 (call edi)
	if (command == 0xd7ff || command == 0xd7cc) {
		ULONG_PTR address;
		__asm {
			mov address, edi
		}
		return address;
	}


	command = *(((WORD*)return_address) - 1);
	// if command is ffd6 (call esi)
	if (command == 0xd6ff || command == 0xd6cc) {
		ULONG_PTR address;
		__asm {
			mov address, esi
		}
		return address;
	}


	DWORD offset = *(returnAddress - 4) + *(returnAddress - 3) * 16 * 16 + *(returnAddress - 2) * 16 * 16 * 16 * 16 + *(returnAddress - 1) * 16 * 16 * 16 * 16 * 16 * 16;
	ULONG_PTR trumplin = ((ULONG_PTR) return_address) + offset;
	BYTE* jmp = (BYTE*)trumplin;

	const ULONG_PTR ntdllAddress = (ULONG_PTR) LoadLibrary(L"ntdll.dll");

	// if trumplin is inside ntdll.dll
	if (ntdllAddress <= trumplin && trumplin <= ntdllAddress + 0x7780000) {
		return trumplin;
	}

	ULONG_PTR originalAddress;

	if (*(returnAddress - 5) == 0x15 && *(returnAddress - 6) == 0xff) {

		ULONG_PTR absJmpAddress = *((ULONG_PTR*)offset);
		jmp = (BYTE*)absJmpAddress;
		originalAddress = (ULONG_PTR)jmp;

	} else if (*jmp == 0xff && *(jmp + 1) == 0x25) {

		DWORD* jmpAddressPtr = (DWORD*)(jmp + 2);
		DWORD* jmpAddress = (DWORD*)(*jmpAddressPtr);
		originalAddress = *jmpAddress;
	}

	return originalAddress;

#else ifdef _M_AMD64 // if x64

	const BYTE* instruction = ((BYTE*)return_address) - 5;

	// it's a relative call
	if (*instruction == 0xe8) {
		const DWORD const* callOffset_ptr = (DWORD*)(instruction + 1);
		const ULONG_PTR ntdDllInitialAddress = (ULONG_PTR) LoadLibrary(L"ntdll.dll");
		const ULONG_PTR calledAddress = ((ULONG_PTR)return_address) + *callOffset_ptr;
		if (ntdDllInitialAddress <= calledAddress && calledAddress <= ntdDllInitialAddress + 0x11A000) return calledAddress;
	}

	// it's an absolute call
	const BYTE secondInstructionByte = *instruction;
	const BYTE firstInstructionByte  = *(instruction - 1);
	//wchar_t mes[100];
	//wsprintf(mes, L"first byte is %#08x, second is %#08x", firstInstructionByte, secondInstructionByte);
	//message(mes);
	if (secondInstructionByte == 0x15 && firstInstructionByte == 0xcc) {
		const DWORD offSet = *((DWORD*)(instruction + 1));
		const ULONG_PTR* absoluteAddress_ptr = (ULONG_PTR*)(((ULONG_PTR)return_address) + offSet);
		return *absoluteAddress_ptr;
	}

#endif

}
*/
/*
__declspec(noinline) int log (const ULONG_PTR originalAddress, const void* returnAddress) {
	WaitForSingleObject(log_mutex, INFINITE);
	int numberOfArgs;
	for (unsigned int i = 0; i < data.size(); i++) {
		if (data[i].address == originalAddress) {
			//MessageBox(NULL, data[i].name, L"Found", MB_OK);
			const DWORD threadID = GetCurrentThreadId();

			// get system time
			SYSTEMTIME sys_time;
			GetSystemTime(&sys_time);

			// capture mutex
			

			// make a log entry
			if (inFakeFunction) {
				inFakeFunction = false;
				//MessageBox(NULL, data[i].name, L"Logging", MB_OK);
				logger.push_back(LogEntry(data[i].name, (ULONG_PTR)returnAddress, sys_time, threadID));
			}
			else {
				inFakeFunction = true;
			}
				
			
			

			numberOfArgs = data[i].numberOfArguments;
			break;
		}
	}
	// release mutex
	ReleaseMutex(log_mutex);
	return numberOfArgs;
}

*/
/*
int __stdcall getInfoAboutNumberOfArgsOriginalFunction(const void* return_address) {
	
	const ULONG_PTR originalAddress = getOriginalAddressByReturnAddress(return_address);

	int numberOfArgs = log(originalAddress, return_address);
	inFakeFunction = true;

	return numberOfArgs;
}

ULONG_PTR __stdcall getBridgeByReturnAddress(const void* return_address) {

	const ULONG_PTR originalAddress = getOriginalAddressByReturnAddress(return_address);

	const ULONG_PTR bridge = GetBridgeByFunction(originalAddress);

	return bridge;
}

void* universal_fake_function(
	void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10, void* arg11, void* arg12
) {

	__asm {
		mov ECX_REGISTRY, ecx;
	}

	void* returnAddress = (void*)_ReturnAddress();

	int numberOfArgs = getInfoAboutNumberOfArgsOriginalFunction(returnAddress);

	ULONG_PTR bridge = getBridgeByReturnAddress(returnAddress);

	switch (numberOfArgs) {
	case 0:
		((void* (WINAPI*)()) bridge)();
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x0
		};

#else ifdef _M_AMD64 // if x64
		//correct_return_x64(returnAddress, 0);
#endif
	case 1:
		((void* (WINAPI*)(void*)) bridge)(arg1);
		__asm {
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x4
		};
		break;
	case 2:
		((void* (WINAPI*)(void*, void*)) bridge)(arg1, arg2);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x8
		};
		break;
#else ifdef _M_AMD64 // if x64
	//	correct_return_x64(returnAddress, 2);
#endif
	case 3:
		((void* (WINAPI*)(void*, void*, void*)) bridge)(arg1, arg2, arg3);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0xc
		};
		break;

#else ifdef _M_AMD64 // if x64
	//	correct_return_x64(returnAddress, 3);
#endif
	case 4:
		((void* (WINAPI*)(void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x10
		};
		break;

#else ifdef _M_AMD64 // if x64
	//	correct_return_x64(returnAddress, 4);
#endif
	case 5:
		((void* (WINAPI*)(void*, void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4, arg5);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x14
		};
		break;

#else ifdef _M_AMD64 // if x64
	//	correct_return_x64(returnAddress, 5);
#endif
	case 6:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4, arg5, arg6);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x18
		};
		break;

#else ifdef _M_AMD64 // if x64
		//correct_return_x64(returnAddress, 6);
#endif
	case 7:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x1c
		};
		break;

#else ifdef _M_AMD64 // if x64
		//correct_return_x64(returnAddress, 7);
#endif
	case 8:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x20
		};
		break;

#else ifdef _M_AMD64 // if x64
		//correct_return_x64(returnAddress, 8);
#endif
	case 9:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*, void*, void*)) bridge)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
#ifdef _M_IX86 // if x86
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x24
		};
		break;

#else ifdef _M_AMD64 // if x64
		//correct_return_x64(returnAddress, 9);
#endif
	case 10:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*, void*, void*, void*)) bridge)
			(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x28
		};
		break;

	case 11:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*)) bridge)
			(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x2c
		};
		break;

	case 12:
		((void* (WINAPI*)(void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*, void*)) bridge)
			(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12);
		__asm {
			//mov eax, result
			pop edi
			pop esi
			pop ebx
			mov esp, ebp
			pop ebp
			retn 0x30
		};
		break;

	}


}
*/
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) {

	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) {
		return FALSE;
	}

	BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

	if (!succeededWriting) {
		return FALSE;
	} else {

		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
		if (loadLibraryAddress == NULL) {
			return FALSE;
		} else {
			HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
			if (remoteThread == NULL) {
				return FALSE;
			}
		}
	}

	//CloseHandle(hProcess);
	return TRUE;
}

std::string GetLastErrorAsString() {
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

std::wstring s2ws(const std::string& s) {
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

void logModules() {
	//message(L"About to log modules!");

	HANDLE currentProcess = GetCurrentProcess();


	HMODULE hMods[128];
	DWORD cbNeeded;

	log_file << "{ \"modules\": [";

	if (EnumProcessModules(currentProcess, hMods, sizeof(hMods), &cbNeeded)) {
		const int min = min(128, (cbNeeded / sizeof(HMODULE)));
		for (int i = 0; i < min; i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(currentProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::for_each(szModName, &szModName[MAX_PATH - 1], [](TCHAR &c) {
					if (c == TEXT('\\')){
						c = TEXT('/');
				    }
				});
				MODULEINFO moduleInfo;

				if (GetModuleInformation(currentProcess, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
					TCHAR temp[256];
					_stprintf(temp, TEXT("{\"name\":\"%s\", \"base\": 0x%08X, \"size\": %d, \"lpBaseOfDll\": 0x%016X},"), szModName, hMods[i], moduleInfo.SizeOfImage, moduleInfo.lpBaseOfDll);
					log_file << temp << std::endl;
				} else {
					message(L"Could not get module info");
				}

				
			} else {
				//message(L"Could not get module fileName");
				std::string error = GetLastErrorAsString();
				//message(s2ws(error).c_str());
			}
		}
	} else {
		//message(L"Could not enum through process modules");
	}
	log_file << "], logs:[";
}

// wide string to string;
static std::string utf16ToUTF8(const std::wstring &s) {
	const int size = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, NULL, 0, 0, NULL);

	std::vector<char> buf(size);
	::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &buf[0], size, 0, NULL);

	return std::string(&buf[0]);
}

static bool shouldQuit = false;



void flush_log() {

	// capture mutex
	WaitForSingleObject(log_mutex, INFINITE);

	for (LogEntry entry : logger) {
		log_file << "{ \"fname\": \"" << entry.function_name 
			<< "\", \"return_address\": " << entry.return_address
			<< ", \"threadID\": " << entry.thread_id 
			<< ", \"moduleName\": \"" << entry.module.module_name << "\""
			<< ", \"moduleBase\": " << entry.module.base_address
			<< ", \"moduleSize\": " << entry.module.size
		<< "}, " << std::endl;
	}

	logger.clear();

	// release mutex
	ReleaseMutex(log_mutex);
}

DWORD WINAPI flushing_loop(LPVOID) {

	while (true) {

		flush_log();

		if (shouldQuit) break;
		Sleep(3000);
	}

	return 0;
}

void log(const wchar_t* fname, ULONG_PTR return_address, SYSTEMTIME time, const DWORD thread_id) {

	Module m;

	HANDLE currentProcess = GetCurrentProcess();
	HMODULE hMods[128];
	DWORD cbNeeded;

	if (EnumProcessModules(currentProcess, hMods, sizeof(hMods), &cbNeeded)) {
		const int min = min(128, (cbNeeded / sizeof(HMODULE)));
		for (int i = 0; i < min; i++) {
			if (return_address >= (ULONG_PTR)hMods[i]) {
				MODULEINFO moduleInfo;
				if (GetModuleInformation(currentProcess, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
					if (return_address <= (ULONG_PTR)hMods[i] + moduleInfo.SizeOfImage) {
						// that's it
						TCHAR szModName[MAX_PATH];
						if (GetModuleFileNameEx(currentProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
							std::for_each(szModName, &szModName[MAX_PATH - 1], [](TCHAR &c) {
								if (c == TEXT('\\')) {
									c = TEXT('/');
								}
							});
							m.base_address = (ULONG_PTR)hMods[i];
							m.size = moduleInfo.SizeOfImage;
							wcsncpy(m.module_name, szModName, 256);
							break;
						}
					}
				}
			}
		}
	}


/*

			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(currentProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::for_each(szModName, &szModName[MAX_PATH - 1], [](TCHAR &c) {
					if (c == TEXT('\\')) {
						c = TEXT('/');
					}
				});
				MODULEINFO moduleInfo;

				if (GetModuleInformation(currentProcess, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
					TCHAR temp[256];
					_stprintf(temp, TEXT("{\"name\":\"%s\", \"base\": 0x%08X, \"size\": %d, \"lpBaseOfDll\": 0x%016X},"), szModName, hMods[i], moduleInfo.SizeOfImage, moduleInfo.lpBaseOfDll);
					if (return_address > (ULONG_PTR)hMods[i] && return_address < (ULONG_PTR)hMods[i] + moduleInfo.SizeOfImage) {
						m.base_address = (ULONG_PTR) hMods[i];
						m.size = moduleInfo.SizeOfImage;
						wcsncpy(m.module_name, szModName, 256);
						break;
					}
				} 
			} 
		}
	}

	*/

	logger.push_back(LogEntry(fname, return_address, time, thread_id, m));

}

void logProcess() {

	WCHAR processName[256];

	GetModuleBaseNameW(GetCurrentProcess(), NULL, processName, 255);

	log_file << "{ \"processName\": \"" << processName << "\", \"callRandomFunctionAddress\":" << std::dec << (long int) callRandomFunction << ", \"calls\" : [" << std::endl;
}

void hack() {

	initializeExploit();

	logger.reserve(1024);

	// create logger mutex
	log_mutex = CreateMutex(NULL, FALSE, NULL);

	if (log_mutex == NULL) {
		//message(L"Error creating mutex!");
		return;
	}

	int currentProcessID = GetCurrentProcessId();
	char filename[256];

	sprintf(filename, "log-%d.json5", currentProcessID);

	log_file.open(filename);

	CreateThread(NULL, 0, flushing_loop, NULL, 0, NULL);

	logProcess();

	if (HookFunction == NULL || UnhookFunction == NULL || GetOriginalFunction == NULL) {

		// read functions to hook from file
		std::wifstream ifs("functions.txt");
		std::wstring functionName;
		message(L"reading function names");
		while (std::getline(ifs, functionName)) {

			data.push_back(FunctionData(functionName.c_str(), 0));

			std::wcout << functionName << " " << 0 << std::endl;
			message(functionName.c_str());
		}

		ifs.close();

		
		HMODULE hHookEngineDll = LoadLibrary(L"NtHookEngine.dll");
		if (hHookEngineDll == NULL) {
			message(L"could not load NtHookEngine");
		}

		// get functions from NtHookEngine
		HookFunction = (BOOL(__cdecl *)(ULONG_PTR, ULONG_PTR)) GetProcAddress(hHookEngineDll, "HookFunction");
		UnhookFunction = (VOID(__cdecl *)(ULONG_PTR)) GetProcAddress(hHookEngineDll, "UnhookFunction");
		GetOriginalFunction = (ULONG_PTR(__cdecl *)(ULONG_PTR)) GetProcAddress(hHookEngineDll, "GetOriginalFunction");
		GetBridgeByFunction = (ULONG_PTR(__cdecl *)(ULONG_PTR)) GetProcAddress(hHookEngineDll, "GetBridgeByFunction");
		wchar_t abc[100];
		wsprintf(abc, L"%x", GetOriginalFunction);
		message(abc);
	}

	if (HookFunction == NULL || UnhookFunction == NULL || GetOriginalFunction == NULL || GetBridgeByFunction == NULL) {
		//message(L"I didnt get the functions =(");
		return;
	}
	
	// hook every function
	for (unsigned int i = 0; i < data.size(); i++) {

		// try function addresses from different libs
		data[i].address = (ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(data[i].name).c_str());
		if (data[i].address == NULL) data[i].address = (ULONG_PTR)GetProcAddress(LoadLibrary(L"User32.dll"), utf16ToUTF8(data[i].name).c_str());

		if (HookFunction(data[i].address, getFakeAddress(data[i].name))) {
			message(L"hook success");
		} else {
			message(L"HOOK FAIL");
		}
	}
	
	HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(L"CreateProcessW").c_str()),
		(ULONG_PTR) &fake_CreateProcessW
		);

	HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(L"CreateProcessA").c_str()),
		(ULONG_PTR)&fake_CreateProcessA
	);
	HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(L"CreateProcessAsUserW").c_str()),
		(ULONG_PTR)&fake_CreateProcessAsUserW
	);
	HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(L"CreateProcessAsUserA").c_str()),
		(ULONG_PTR)&fake_CreateProcessAsUserA
	);

	/*
	if (HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"mozglue.dll"), utf16ToUTF8(L"malloc").c_str()),
		(ULONG_PTR)&fake_malloc
	)) {
		message(L"Exploit hook success");
	} else {
		message(L"Exploit hook fail");
	}*/
	
	/*HookFunction(
		(ULONG_PTR)GetProcAddress(LoadLibrary(L"Kernel32.dll"), utf16ToUTF8(L"ReadFile").c_str()),
		(ULONG_PTR)&fake_ReadFile
	);*/

}

void onDetach() {
	message(L"detaching");

	shouldQuit = true;

	Sleep(4000);

	// destroy logger mutex
	CloseHandle(log_mutex);

	// flush log before exiting
	flush_log();

	log_file << "]}";

	log_file.close();
}

BOOL APIENTRY WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD ul_reason_for_call,
	LPVOID lpReserved) {

	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		//MessageBox(NULL, "THIS IS DLL_PROCESS_ATTACH", "DLL MESSAGE", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
		//MessageBox(NULL, "THIS IS DLL_THREAD_ATTACH", "DLL MESSAGE", MB_OK);
		break;
	case DLL_THREAD_DETACH:
		//onDetach();
		break;
	case DLL_PROCESS_DETACH:
		onDetach();
		break;
	}

	if (shouldHack) {
		message(L"about to hack a process!");
		hack();
		shouldHack = 0;
	}

	return TRUE;
}
