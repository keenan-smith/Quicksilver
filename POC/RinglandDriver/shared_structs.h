#pragma once
#include "stdint.h"

constexpr auto packet_magic = 0x12345568;
constexpr auto server_ip = 0x7F000001; // 127.0.0.1
constexpr auto server_port = 25560;
constexpr auto close_server_magic = 0xCAFEBABE;

enum class PacketType
{
	packet_copy_memory,
	packet_allocate_memory,
	packet_protect_memory,
	packet_get_base_address,
	packet_create_thread,
	packet_echo,
	packet_close_server,
	packet_completed
};

struct PacketProtectMemory
{
	uint32_t process_id;
	uint64_t address;
	uint64_t size;
	uint32_t protect;
};

struct PacketAllocateMemory
{
	uint32_t process_id;
	uint64_t size;
	uint32_t allocation_type;
	uint32_t protect;
	uint64_t address;
};

struct PacketCopyMemory
{
	uint32_t dest_process_id;
	uint64_t dest_address;

	uint32_t src_process_id;
	uint64_t src_address;

	uint32_t size;
};

struct PacketCreateThread
{
	uint32_t process_id;
	uint64_t entry_point;
	uint64_t base_address;
};

struct PacketCloseServer
{
	uint32_t magic;
};

struct PacketEcho
{
	char text[512];
};

struct PacketGetBaseAddress
{
	uint32_t process_id;
};

struct PackedCompleted
{
	uint64_t result;
};

struct PacketHeader
{
	uint32_t   magic;
	PacketType type;
};

struct Packet
{
	PacketHeader header;
	union
	{
		PacketProtectMemory	 protect_memory;
		PacketAllocateMemory allocate_memory;
		PacketCreateThread	 create_thread;
		PacketCopyMemory	 copy_memory;
		PacketGetBaseAddress get_base_address;
		PacketEcho			 echo;
		PacketCloseServer	 close_server;
		PackedCompleted		 completed;
	} data;
};