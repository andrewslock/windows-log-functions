#pragma once

//#include "stdafx.h"

BOOL WINAPI fake_CreateProcessW(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL(WINAPI *realCreateProcessW)(
		_In_opt_ LPCWSTR,
		_Inout_opt_ LPWSTR,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_ BOOL,
		_In_ DWORD,
		_In_opt_ LPVOID,
		_In_opt_ LPCWSTR,
		_In_ LPSTARTUPINFOW,
		_Out_ LPPROCESS_INFORMATION
		);

	realCreateProcessW = (BOOL(WINAPI*)(
		_In_opt_ LPCWSTR,
		_Inout_opt_ LPWSTR,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_ BOOL,
		_In_ DWORD,
		_In_opt_ LPVOID,
		_In_opt_ LPCWSTR,
		_In_ LPSTARTUPINFOW,
		_Out_ LPPROCESS_INFORMATION
		)) GetOriginalFunction((ULONG_PTR)fake_CreateProcessW);

	PROCESS_INFORMATION processInformation;



	const BOOL result = realCreateProcessW(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		CREATE_SUSPENDED | dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		&processInformation
	);

	if (!result) {
		//message(L"unsuccessful createProcessW");
	} else {
		//message(L"successful createProcessW");
	}

	HANDLE hProcess = processInformation.hProcess;

	BOOL injectSuccessful = loadRemoteDLL(hProcess, "hookdll.dll");

	if (dwCreationFlags == CREATE_SUSPENDED) {

	} else {

	}

	*lpProcessInformation = processInformation;
	ResumeThread(processInformation.hThread);
	return result;

}

BOOL WINAPI fake_CreateProcessA(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL(WINAPI *realCreateProcessA)(
		_In_opt_ LPCSTR,
		_Inout_opt_ LPSTR,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_ BOOL,
		_In_ DWORD,
		_In_opt_ LPVOID,
		_In_opt_ LPCSTR,
		_In_ LPSTARTUPINFOA,
		_Out_ LPPROCESS_INFORMATION
		);

	realCreateProcessA = (BOOL(WINAPI*)(
		_In_opt_ LPCSTR,
		_Inout_opt_ LPSTR,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_opt_ LPSECURITY_ATTRIBUTES,
		_In_ BOOL,
		_In_ DWORD,
		_In_opt_ LPVOID,
		_In_opt_ LPCSTR,
		_In_ LPSTARTUPINFOA,
		_Out_ LPPROCESS_INFORMATION
		)) GetOriginalFunction((ULONG_PTR)fake_CreateProcessA);


	PROCESS_INFORMATION processInformation;

	//message(L"before CreateProcessA");

	const BOOL result = realCreateProcessA(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		CREATE_SUSPENDED | dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		&processInformation
	);

	if (!result) {
		//message(L"unsuccessful createProcessA");
	} else {
		//message(L"successful createProcessA");
	}

	HANDLE hProcess = processInformation.hProcess;

	BOOL injectSuccessful = loadRemoteDLL(hProcess, "hookdll.dll");

	if (dwCreationFlags == CREATE_SUSPENDED) {

	} else {

	}

	*lpProcessInformation = processInformation;
	ResumeThread(processInformation.hThread);
	return result;

}

BOOL WINAPI fake_CreateProcessAsUserW(
	_In_opt_ HANDLE hToken,
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL(WINAPI *realCreateProcessAsUserW)(
		_In_opt_ HANDLE hToken,
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		);

	realCreateProcessAsUserW = (BOOL(WINAPI*)(
		_In_opt_ HANDLE hToken,
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		)) GetOriginalFunction((ULONG_PTR)fake_CreateProcessAsUserW);


	PROCESS_INFORMATION processInformation;

	//message(L"before CreateProcessAsUserW");

	const BOOL result = realCreateProcessAsUserW(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		CREATE_SUSPENDED | dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		&processInformation
	);

	if (!result) {
		//message(L"unsuccessful createProcessAsUserW");
	} else {
		//message(L"successful createProcessAsUserW");
	}

	HANDLE hProcess = processInformation.hProcess;

	BOOL injectSuccessful = loadRemoteDLL(hProcess, "hookdll.dll");

	if (dwCreationFlags == CREATE_SUSPENDED) {

	} else {

	}

	*lpProcessInformation = processInformation;
	ResumeThread(processInformation.hThread);
	return result;

}


BOOL WINAPI fake_CreateProcessAsUserA(
	_In_opt_ HANDLE hToken,
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL(WINAPI *realCreateProcessAsUserA)(
		_In_opt_ HANDLE hToken,
		_In_opt_ LPCSTR lpApplicationName,
		_Inout_opt_ LPSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOA lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		);

	realCreateProcessAsUserA = (BOOL(WINAPI*)(
		_In_opt_ HANDLE hToken,
		_In_opt_ LPCSTR lpApplicationName,
		_Inout_opt_ LPSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOA lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		)) GetOriginalFunction((ULONG_PTR)fake_CreateProcessAsUserA);


	PROCESS_INFORMATION processInformation;

	//message(L"before CreateProcessAsUserA");

	const BOOL result = realCreateProcessAsUserA(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		CREATE_SUSPENDED | dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		&processInformation
	);

	if (!result) {
		//message(L"unsuccessful createProcessAsUserA");
	} else {
		//message(L"successful createProcessAsUserA");
	}

	HANDLE hProcess = processInformation.hProcess;

	BOOL injectSuccessful = loadRemoteDLL(hProcess, "hookdll.dll");

	if (dwCreationFlags == CREATE_SUSPENDED) {

	} else {

	}

	*lpProcessInformation = processInformation;
	ResumeThread(processInformation.hThread);
	return result;

}

