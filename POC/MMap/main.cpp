#include "drvhelper.h"
#include <Windows.h>
#include <fstream>
#include "logger.h"
#include "mmap.h"

using namespace std;

const char* filename = "MonoLoader.dll";
const char* procname = "notepad.exe";

int main(int argc, char* argv[]) {
	//ifstream file(filename, ios::binary | ios::ate);

	uintptr_t pEntryPoint, pBaseAddress;

	mmap mapper(INJECTION_TYPE::USERMODE);

	driver::initialize();

	sConnection = driver::connect();
	if (sConnection == INVALID_SOCKET) {
		LOG("Connection failed.");
		return -1;
	}

	LOG("Connected to driver, Attaching to process : " + string(procname));

	if (!mapper.attach_to_process(procname)) {
		driver::disconnect(sConnection);
		return -1;
	}

	LOG("Attached to process, loading dll.");

	if (!mapper.load_dll(filename)) {
		driver::disconnect(sConnection);
		return -1;
	}

	LOG("Loaded dll, injecting into process.");

	if (!mapper.inject(pEntryPoint, pBaseAddress)) {
		driver::disconnect(sConnection);
		return -1;
	}

	LOG("Injected dll, calling entrypoint.");

	uint32_t pid;
	if (!is_process_running(procname, pid)) {
		driver::disconnect(sConnection);
		return -1;
	}

	driver::create_thread(sConnection, pid, pEntryPoint, pBaseAddress);

	LOG("Calling out to RinglandDriver, looking for a response!");
	const char* echoText = "ping!";

	const auto return_status = driver::echo(sConnection, echoText);
	LOG("Echo returned status: 0x%X", return_status);

	Sleep(1000);

	//LOG("Sending request to shut down server...");
	//LOG("Request returned status: 0x%X", driver::close_server(sConnection));

	driver::disconnect(sConnection);

	/*const auto connection2 = driver::connect();
	if (connection2 == INVALID_SOCKET) {
		LOG("Connection failed.");
		return -1;
	}

	const auto return_stat = driver::echo(connection2, echoText);
	LOG("Echo returned status: 0x%X", return_status);

	driver::disconnect(connection2);*/

	driver::deinitialize();

	//system("pause");

	return 1;
}