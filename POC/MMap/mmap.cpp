#include "mmap.h"
#include <TlHelp32.h>

bool mmap::attach_to_process(const char* process_name) {
	this->process_name = process_name;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_stricmp(entry.szExeFile, process_name) == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                if (!hProcess) {
                    logger::LOG_ENTRY("Error obtaining a handle to process");
                    return false; 
                }
                this->hProcess = hProcess;
            }
        }
    }

    CloseHandle(snapshot);
	return true;
}

bool mmap::load_dll(const char* file_name) {
    std::ifstream f(file_name, std::ios::binary | std::ios::ate);
    if (!f) {
        logger::LOG_ENTRY("Error opening file");
        return false;
    }


}