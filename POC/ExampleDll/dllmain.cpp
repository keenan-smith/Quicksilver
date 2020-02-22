#include <Windows.h>

DWORD WINAPI Test(LPVOID args) {
    MessageBox(0, L"This is a test!", L"Test", MB_OK);
    return TRUE;
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(0, 0, &Test, 0, 0, NULL);
    }
    return TRUE;
}