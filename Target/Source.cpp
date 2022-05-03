#include <Windows.h>
#include <stdio.h>

void message(const char* str) {
	MessageBox(NULL, str, "MESSAGE", MB_OK);
}


static bool keepGoing = true;

DWORD WINAPI foo(LPVOID) {

	while (keepGoing) {
		ReadFile(NULL, NULL, NULL, NULL, NULL);
		Sleep(100);
	}

	return 0;
	
}

DWORD WINAPI foo2(LPVOID) {

	DWORD bytesRead;

	while (keepGoing) {
		ReadFile(NULL, NULL, NULL, &bytesRead, NULL);
		Sleep(100);
	}

	return 0;

}

DWORD WINAPI doNothing(LPVOID) {

	while (keepGoing) {
		
		Sleep(500);
	}

	return 0;
}

int main(int argc, char *argv[]) {

	HANDLE h1 = CreateThread(
		NULL,    // Thread attributes
		0,       // Stack size (0 = use default)
		foo, // Thread start address
		NULL,    // Parameter to pass to the thread
		0,       // Creation flags
		NULL);   // Thread id


	HANDLE h2 = CreateThread(
		NULL,    // Thread attributes
		0,       // Stack size (0 = use default)
		foo2, // Thread start address
		NULL,    // Parameter to pass to the thread
		0,       // Creation flags
		NULL);

	printf("Waiting 10 secs\n");
	Sleep(10000);
	printf("Exiting...\n");
	keepGoing = false;

	WaitForSingleObject(h1, INFINITE);
	WaitForSingleObject(h2, INFINITE);

	CloseHandle(h1);
	CloseHandle(h2);

	return 0;

};