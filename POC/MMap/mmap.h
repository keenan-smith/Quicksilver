#pragma once
#include <Windows.h>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include "logger.h"

class mmap {
	HANDLE hProcess;
	std::string process_name;
	uint8_t* raw_data;
	size_t data_size;
	
public:
	bool attach_to_process(const char* proc_name);
	bool load_dll(const char* file_name);
	bool inject();

	uint64_t* ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* image_base);
	PIMAGE_SECTION_HEADER enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header);

	void solve_imports(uint8_t* base, IMAGE_NT_HEADERS* nt_header, IMAGE_IMPORT_DESCRIPTOR* impDesc);
	//void solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS* nt_header, IMAGE_BASE_RELOCATION* reloc, size_t size);
	//void map_pe_sections(uint64_t base, IMAGE_NT_HEADERS* nt_header);

	//uint64_t get_proc_address(const char* module_name, const char* func);
	//bool parse_imports();

	template <typename T>
	T read_mem(uint64_t src, uint64_t size = sizeof(T)) {
		T ret;
		ReadProcessMemory(hProcess, (LPVOID)src, (LPVOID)&ret, size, NULL);
		return ret;
	}
};