#include <Windows.h>
#include <fstream>

using namespace std;

const char* filename = "ExampleDll.dll";

int main(int argc, char* argv[]) {
	ifstream file(filename, ios::binary | ios::ate);

	return 1;
}