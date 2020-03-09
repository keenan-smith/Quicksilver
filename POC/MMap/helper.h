#pragma once
#include <Windows.h>
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

struct EntryPointData
{
	LPVOID ImageBase;
	LPVOID EntryPoint;
};

DWORD __stdcall EntryPointCaller()
{
	volatile uintptr_t Manual_Inject = 0xDEEEEEEEEEADBEEF;
	EntryPointData* EPD = (EntryPointData*)Manual_Inject;

	if (EPD->EntryPoint)
	{
		dllmain EntryPoint = (dllmain)EPD->EntryPoint;
		return EntryPoint((HMODULE)EPD->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}
	return FALSE;
}

DWORD __stdcall stub()
{
	return 0;
}