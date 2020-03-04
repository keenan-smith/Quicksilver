#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include "logger.h"
#include "monofuncs.h"
#include "hwid.h"

DWORD WINAPI MainThread(LPVOID params) {
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	DebugLog("Initialized");
	Sleep(1);
	HMODULE hMono = nullptr;

	//AllocConsole();

	while (hMono == nullptr) {
		DebugLog("Looking for mono.dll...");
		hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
		if (hMono == nullptr)
			Sleep(250);
	}

	DebugLog("Found mono.dll at 0x%X", hMono);

	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {

		CreateThread(NULL, NULL, MainThread, NULL, NULL, NULL);
}


