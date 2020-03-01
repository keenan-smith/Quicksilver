#pragma once
extern bool should_server_be_running;
extern bool shut_down_server;

long ZwCreateRemoteThread(
	unsigned int process_id,
	unsigned long long entry_point,
	unsigned long long base_address
);

long ZwVirtualAlloc(
    unsigned int process_id,
    unsigned long long &size,
    unsigned int allocation_type,
    unsigned int protect,
    unsigned long long &address
);

long ZwVirtualProtect(
    unsigned int process_id,
    unsigned long long address,
    unsigned long long size,
    unsigned int protect
);

void MakeDynamicData();