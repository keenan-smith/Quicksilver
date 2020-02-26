#pragma once
#include "sockets.h"
#include "log.h"

void NTAPI thread_server(void*);
SOCKET make_listen_sock();