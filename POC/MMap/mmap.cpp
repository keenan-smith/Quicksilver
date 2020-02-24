#include "mmap.h"
#include "utils.h"
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
                    LOGENTRY("Error obtaining a handle to process");
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
        LOGENTRY("Error opening DLL file");
        return false;
    }

    std::ifstream::pos_type pos{ f.tellg() };
    data_size = pos;

    raw_data = new uint8_t[data_size];

    if (!raw_data) {
        LOGENTRY("Error allocating space for DLL");
        return false;
    }

    f.seekg(0, std::ios::beg);
    f.read((char*)raw_data, data_size);

    f.close();
    return true;
}

bool mmap::inject() {
    if (hProcess == NULL) {
        LOGENTRY("Handle is invalid");
        return false;
    }

    if (!raw_data) {
        LOGENTRY("Dll buffer is empty");
        return false;
    }

    IMAGE_DOS_HEADER* dos_header{ (IMAGE_DOS_HEADER*)raw_data };
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        LOGENTRY("Invalid DOS header signature");
        return false;
    }

    IMAGE_NT_HEADERS* nt_header{ (IMAGE_NT_HEADERS*)(&raw_data[dos_header->e_lfanew]) };
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        LOGENTRY("Invalid NT header signature");
        return false;
    }

    uint64_t base{ (uint64_t)VirtualAllocEx(hProcess, NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
    if (!base) {
        LOGENTRY("Unable to allocate memory in remote process for the image");
        return false;
    }

    LOGENTRY("Image base: 0x" + utils::int_to_hex<uint64_t>(base));


}

uint64_t* mmap::ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* image_base) {
    PIMAGE_SECTION_HEADER section_header{ enclosing_section_header(rva, nt_header) };
    
    if (!section_header)
        return 0;

    int64_t delta{ (int64_t)(section_header->VirtualAddress - section_header->PointerToRawData) };
    return (uint64_t*)(image_base + rva - delta);
}

PIMAGE_SECTION_HEADER mmap::enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header) {
    PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION(nt_header) };

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++) {
        uint64_t size{ section->Misc.VirtualSize };
        if (!size)
            size = section->SizeOfRawData;
        if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
            return section;
    }

    return 0;
}

void mmap::solve_imports(uint8_t* base, IMAGE_NT_HEADERS* nt_header, IMAGE_IMPORT_DESCRIPTOR* import_descriptor) {
    char* module;
    while ((module = (char*)ptr_from_rva((DWORD64)(import_descriptor->Name), nt_header, (PBYTE)base))) {
        HMODULE local_module{ LoadLibrary(module) };

        IMAGE_THUNK_DATA* thunk_data{ (IMAGE_THUNK_DATA*)ptr_from_rva((DWORD64)((thunk_data->u1.AddressOfData)), nt_header, (PBYTE)base) };

        while (thunk_data->u1.AddressOfData) {
            IMAGE_IMPORT_BY_NAME* iibn{ (IMAGE_IMPORT_BY_NAME*)ptr_from_rva((DWORD64)((thunk_data->u1.AddressOfData)), nt_header, (PBYTE)base) };
            thunk_data->u1.Function = (uint64_t)(get_proc_address(module, (char*)iibn->Name));
            thunk_data++;
        }
        import_descriptor++;
    }
}