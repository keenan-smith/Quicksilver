#include "driver.h"
#include <Windows.h>
#include <fstream>
#include "logger.h"
#include "mmap.h"

using namespace std;

const char* filename = "ExampleDll.dll";

int main(int argc, char* argv[]) {
	//ifstream file(filename, ios::binary | ios::ate);

	uintptr_t pEntryPoint, pBaseAddress;

	mmap mapper(INJECTION_TYPE::USERMODE);

	if (!mapper.attach_to_process("notepad.exe"))
		return 1;

	if (!mapper.load_dll(filename))
		return 1;

	if (!mapper.inject(pEntryPoint, pBaseAddress))
		return 1;

	uint32_t pid;
	if (!is_process_running("notepad.exe", pid))
		return 1;

	driver::initialize();

	const auto connection = driver::connect();
	if (connection == INVALID_SOCKET) {
		LOG("Connection failed.");
	}

	driver::create_thread(connection, pid, pEntryPoint, pBaseAddress);

	LOG("Calling out to RinglandDriver, looking for a response!");
	const char* echoText = "ping!";

	const auto return_status = driver::echo(connection, echoText);
	LOG("Echo returned status: 0x%X", return_status);

	Sleep(1000);

	LOG("Sending request to shut down server...");
	LOG("Request returned status: 0x%X", driver::close_server(connection));

	driver::disconnect(connection);

	const auto connection2 = driver::connect();
	if (connection == INVALID_SOCKET) {
		LOG("Connection failed.");
	}

	const auto return_stat = driver::echo(connection, echoText);
	LOG("Echo returned status: 0x%X", return_status);

	driver::disconnect(connection2);

	driver::deinitialize();

	system("pause");

	return 1;
}