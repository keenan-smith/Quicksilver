#pragma once
extern bool should_server_be_running;
extern bool shut_down_server;

long ZwCreateRemoteThread(
	unsigned int process_id,
	unsigned long long entry_point,
	unsigned long long base_address
);

void MakeDynamicData();