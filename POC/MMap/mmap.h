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


};