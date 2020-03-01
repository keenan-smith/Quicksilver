#pragma once
#include <WinSock2.h>
#include <cstdint>

namespace driver
{
	void	initialize();
	void	deinitialize();

	SOCKET	connect();
	void	disconnect(SOCKET connection);

	uint32_t read_memory(SOCKET connection, uint32_t process_id, uintptr_t address, uintptr_t buffer, size_t size);
	uint32_t write_memory(SOCKET connection, uint32_t process_id, uintptr_t address, uintptr_t buffer, size_t size);
	uint64_t create_thread(SOCKET connection, uint32_t process_id, uintptr_t address, uintptr_t buffer);
	uint64_t virtual_protect(SOCKET connection, uint32_t process_id, uint64_t address, size_t size, uint32_t protect);
	uint64_t virtual_alloc(SOCKET connection, uint32_t process_id, size_t size, uint32_t allocation_type, uint32_t protect, uint64_t address);
	uint64_t get_process_base_address(SOCKET connection, uint32_t process_id);
	uint64_t echo(SOCKET connection, const char* text);
	uint64_t close_server(SOCKET connection);

	template <typename T>
	T read(const SOCKET connection, const uint32_t process_id, const uintptr_t address)
	{
		T buffer{ };
		read_memory(connection, process_id, address, uint64_t(&buffer), sizeof(T));

		return buffer;
	}

	template <typename T>
	void write(const SOCKET connection, const uint32_t process_id, const uintptr_t address, const T& buffer)
	{
		write_memory(connection, process_id, address, uint64_t(&buffer), sizeof(T));
	}
}
