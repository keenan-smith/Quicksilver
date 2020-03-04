#include "shared_structs.h"
#include "sockets.h"

uint64_t	handle_incoming_packet(const Packet& packet, uint64_t& status);
bool		complete_request(SOCKET client_connection, uint64_t result, uint64_t status);