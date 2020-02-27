#include <sstream>
#include <iomanip>
#include <Windows.h>
#include <TlHelp32.h>

template< typename T >
std::string int_to_hex(T i);

bool is_process_running(const char* process_name, uint32_t& pid);

