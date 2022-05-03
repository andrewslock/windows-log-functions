#pragma once

#ifndef STDAFX
#define STDAFX



#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>



// reference additional headers your program requires here

#include <stdio.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <Psapi.h>
#include <tchar.h>
#include <ctime>

#include "exploit.h"

static BOOL(__cdecl *HookFunction)(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction) = NULL;
static VOID(__cdecl *UnhookFunction)(ULONG_PTR Function) = NULL;
static ULONG_PTR(__cdecl *GetOriginalFunction)(ULONG_PTR Hook) = NULL;
static ULONG_PTR(__cdecl *GetBridgeByFunction)(ULONG_PTR Hook) = NULL;


typedef struct FunctionData {
	wchar_t name[100];
	ULONG_PTR address;
	int numberOfArguments;
	FunctionData(const wchar_t* name, int numberOfArguments) {
		wcscpy_s(this->name, 100, name);
		this->numberOfArguments = numberOfArguments;
	}
} FunctionData;

extern std::vector<FunctionData> data;


void message_unique(const wchar_t* str);


typedef struct Module {
	wchar_t module_name[256];
	ULONG_PTR base_address;
	size_t size;
};

typedef struct LogEntry {

	wchar_t function_name[100];
	ULONG_PTR return_address;
	SYSTEMTIME time;
	DWORD thread_id;

	Module module;

	LogEntry(const wchar_t* function_name, ULONG_PTR return_address, SYSTEMTIME time, DWORD thread_id, Module m) :
		return_address(return_address), time(time), thread_id(thread_id), module(m) {

		wcscpy_s(this->function_name, 100, function_name);

	}

};

//  log file
static std::wofstream log_file;

// Log
static std::vector<LogEntry> logger;

// Logger mutex
static HANDLE log_mutex;

// callback timer id
static ULONG_PTR timer_id;

static thread_local bool inFakeFunction = true;
static thread_local ULONG ECX_REGISTRY;


static int shouldHack = 1;

//extern "C" void* WINAPI asm_test();

void message(LPCWSTR str);

DWORD WINAPI GetThreadStartAddress(HANDLE hThread);

BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);

ULONG_PTR getFakeAddress(std::wstring functionName);

void callRandomFunction(int functionNumber);

void log(const wchar_t* fname, ULONG_PTR return_address, SYSTEMTIME time, const DWORD thread_id);

#endif // !STDAFX