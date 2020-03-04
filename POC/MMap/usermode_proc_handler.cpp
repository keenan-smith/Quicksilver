#include "drvhelper.h"
#include "usermode_proc_handler.h"
#include "logger.h"
#include "apiset.h"

usermode_proc_handler::usermode_proc_handler()
	:handle{ NULL }, pid{ 0 } {}

usermode_proc_handler::~usermode_proc_handler() { if (handle) CloseHandle(handle); }

bool usermode_proc_handler::is_attached() { return pid; }

bool usermode_proc_handler::attach(const char* proc_name) {
	while (!is_process_running(proc_name, pid))
		std::this_thread::sleep_for(std::chrono::seconds(1));

	//handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

	return 1;
}

uint64_t usermode_proc_handler::get_module_base(std::string& module_name) {
	std::string original_module_name = module_name;
	if ((module_name.find("api-ms") != std::string::npos)) {
		//pilfered from https://github.com/zodiacon/WindowsInternals/blob/master/APISetMap/APISetMap.cpp
		module_name = get_dll_name_from_api_set_map(module_name);
		LOG("Resolved API set, %s == %s", original_module_name.c_str(), module_name.c_str());
		if (module_name.empty()) {
			LOG("api.map.set==false");
		}
	}
	//MODULEENTRY32 module_entry{};
	//module_entry.dwSize = sizeof(MODULEENTRY32);
	//auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
	//if (snapshot == INVALID_HANDLE_VALUE)
	//	return false;
	//if (Module32First(snapshot, &module_entry)) {
	//	do {
	//		//LOG("Checking module: %s", module_entry.szModule);
	//		if (!_stricmp(module_entry.szModule, module_name.c_str())) {
	//			CloseHandle(snapshot);
	//			return (uint64_t)module_entry.hModule;
	//		}
	//		module_entry.dwSize = sizeof(MODULEENTRY32);
	//	} while (Module32Next(snapshot, &module_entry));
	//}
	//CloseHandle(snapshot);
	//return NULL;
	
	uint64_t module_base = driver::get_module_handle(sConnection, pid, module_name.c_str());
	LOG("Getting base address of %s, address 0x%X", module_name.c_str(), module_base);
	return module_base;
}
	
void usermode_proc_handler::read_memory(uintptr_t src, uintptr_t dst, size_t size) {
	if (driver::read_memory(sConnection, pid, src, dst, size) != 0)
		LOG("Error reading memory!");

	/*if (!ReadProcessMemory(handle, (LPCVOID)src, (LPVOID)dst, size, NULL))
		LOG("Error reading memory!");*/
		
}

void usermode_proc_handler::write_memory(uintptr_t dst, uintptr_t src, size_t size) {
	if (driver::write_memory(sConnection, pid, dst, src, size) != 0)
		LOG("Error writing memory!");

	/*if (!WriteProcessMemory(handle, (LPVOID)dst, (LPVOID)src, size, NULL))
		LOG("Error writing memory!");*/
}

void usermode_proc_handler::create_thread(uintptr_t start, uintptr_t arg) {
	CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)start, (LPVOID)arg, 0, NULL);
}

uint32_t usermode_proc_handler::virtual_protect(uint64_t address, size_t size, uint32_t protect) { //who cares about old protect anyways hahahahhahahahaaaaaa
	DWORD old_protect{0};
	if (driver::virtual_protect(sConnection, pid, address, size, protect) != 0)
		LOG("Error in virtual_protect!");
	//VirtualProtectEx(handle, (LPVOID)address, size, protect, &old_protect);
	return old_protect;
}

uint64_t usermode_proc_handler::virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address) {
	return driver::virtual_alloc(sConnection, pid, size, allocation_type, protect, address);
	//return (uint64_t)VirtualAllocEx(handle, (void*)address, size, allocation_type, protect);
}