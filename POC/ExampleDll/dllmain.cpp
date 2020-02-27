#include <windows.h>
#include <stdint.h>


/* Compile as x64 Release !!! */

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {

	MessageBox(0, L"Done.", L"Injected", MB_OK | MB_ICONERROR);
}


