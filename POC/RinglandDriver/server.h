#pragma once
#include "sockets.h"
#include "log.h"

void NTAPI	thread_server(void*);
void NTAPI	thread_connection(void*);
SOCKET		make_listen_sock();