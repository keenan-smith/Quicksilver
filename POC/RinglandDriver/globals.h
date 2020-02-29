#pragma once
extern bool should_server_be_running;
extern bool shut_down_server;

NTSTATUS ZwCreateRemoteThread
(
	UINT32 process_id,
	UINT64 entry_point,
	UINT64 base_address
);

void MakeDynamicData();