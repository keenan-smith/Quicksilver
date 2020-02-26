#include "driver.h"
#include <Windows.h>
#include <fstream>
#include "logger.h"

using namespace std;

const char* filename = "ExampleDll.dll";

int main(int argc, char* argv[]) {
	ifstream file(filename, ios::binary | ios::ate);

	driver::initialize();

	const auto connection = driver::connect();
	if (connection == INVALID_SOCKET) {
		LOGENTRY("Connection failed.");
	}

	LOGENTRY("Calling out to RinglandDriver, looking for a response!");
	const char* echoText = "ping!";

	const auto return_status = driver::echo(connection, echoText);
	LOGENTRY("Echo returned status: 0x%X", return_status);

	driver::disconnect(connection);

	driver::deinitialize();

	system("pause");

	return 1;
}