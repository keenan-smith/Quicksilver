#pragma once
extern bool should_server_be_running;
extern bool shut_down_server;

extern unsigned long long kernel_create_remote_thread(unsigned int pid, unsigned long long start, unsigned long long arg);