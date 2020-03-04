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

	return 1;
}

uint64_t usermode_proc_handler::get_module_base(std::string& module_name) {
	
	uint64_t module_base = driver::get_module_handle(sConnection, pid, module_name.c_str());
	return module_base;
}
	
void usermode_proc_handler::read_memory(uintptr_t src, uintptr_t dst, size_t size) {
	if (driver::read_memory(sConnection, pid, src, dst, size) != 0)
		LOG("Error reading memory!");
		
}

void usermode_proc_handler::write_memory(uintptr_t dst, uintptr_t src, size_t size) {
	if (driver::write_memory(sConnection, pid, dst, src, size) != 0)
		LOG("Error writing memory!");
}

void usermode_proc_handler::create_thread(uintptr_t start, uintptr_t arg) {
	CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)start, (LPVOID)arg, 0, NULL);
}

uint32_t usermode_proc_handler::virtual_protect(uint64_t address, size_t size, uint32_t protect) {
	DWORD old_protect{0};
	if (driver::virtual_protect(sConnection, pid, address, size, protect) != 0)
		LOG("Error in virtual_protect!");
	return old_protect;
}

uint64_t usermode_proc_handler::virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address) {
	return driver::virtual_alloc(sConnection, pid, size, allocation_type, protect, address);
}

uint32_t usermode_proc_handler::get_pid() {
	return pid;
}