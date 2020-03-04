#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include "logger.h"

DWORD WINAPI MainThread(LPVOID params) {
	Sleep(1);
	HMODULE hMono = nullptr;

	//AllocConsole();

	//while (hMono == nullptr) {
	//	//DebugLog("Looking for mono.dll...");
	//	hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
	//	if (hMono == nullptr)
	//		Sleep(250);
	//}

	/*char buffer[512];
	sprintf(buffer, "mono.dll found at 0x%X", hMono);

	MessageBoxA(NULL, buffer, "ERROR", NULL);*/
	AllocConsole();

	/*std::string string("test");
	std::ofstream of;
	of.open("monolog.txt");
	of << "Test\n";
	of.close()*/;
	freopen("CONOUT$", "w", stdout);
	printf("test\n%s\n", "tst2");

	//DebugLog("Found mono.dll");

	/*DebugLog("mono.dll located at: 0x%X", hMono);

	DebugLog("Attempting to inject C# assembly...");*/

	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {

		CreateThread(NULL, NULL, MainThread, NULL, NULL, NULL);
}


