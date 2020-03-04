#include "server.h"
#include "packet_handler.h"
#include "globals.h"

SOCKET make_listen_sock() {
	SOCKADDR_IN addr{};

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(server_port);

	int listen_socket = socket_listen(AF_INET, SOCK_STREAM, 0);
	if (listen_socket == INVALID_SOCKET) {
		log("Unable to create listen socket.");
		return INVALID_SOCKET;
	}

	if (bind(listen_socket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		log("Unable to bind socket.");
		closesocket(listen_socket);
		return INVALID_SOCKET;
	}

	if (listen(listen_socket, 10) == SOCKET_ERROR) {
		log("Unable to set socket to listen mode.");
		closesocket(listen_socket);
		return INVALID_SOCKET;
	}

	return listen_socket;
}

void NTAPI thread_connection(void* connection_socket) {
	SOCKET client_connection = SOCKET(ULONG_PTR(connection_socket));
	log("Connecting.");

	Packet packet{};
	while (true)
	{
		const auto result = recv(client_connection, (void*)&packet, sizeof(packet), 0);
		if (result <= 0)
			break;

		if (result < sizeof(PacketHeader))
			continue;

		if (packet.header.magic != packet_magic)
			continue;

		uint64_t status = 0;

		const auto packet_result = handle_incoming_packet(packet, status);
		if (!complete_request(client_connection, packet_result, status))
			break;
	}

	log("Connection closed.");
	closesocket(client_connection);

	if (shut_down_server)
	{
		log("End of connection thread, telling main thread to shut down.");
		should_server_be_running = false;
	}
}

void NTAPI thread_server(void*) {
	NTSTATUS status = KsInitialize();
	if (!NT_SUCCESS(status)) {
		log("KSOCKET failed to initialize. Status code: 0x%X.", status);
		return;
	}

	SOCKET listen_sock = make_listen_sock();
	if (listen_sock == INVALID_SOCKET) {
		log("Unable to initialize listen socket.");
		KsDestroy();
		return;
	}

	log("Listening on port %d.", server_port);

	MakeDynamicData();

	while (should_server_be_running) {
		sockaddr  socket_addr{};
		socklen_t socket_length{};

		int client_connection = accept(listen_sock, &socket_addr, &socket_length);
		if (client_connection == INVALID_SOCKET) {
			log("Unable to accept client connection.");
			break;
		}

		HANDLE thread_handle = nullptr;

		status = PsCreateSystemThread(
			&thread_handle,
			GENERIC_ALL,
			nullptr,
			nullptr,
			nullptr,
			thread_connection,
			(void*)client_connection
		);

		if (!NT_SUCCESS(status)) {
			log("Unable to create thread for handling client connection.");
			closesocket(client_connection);
			break;
		}

		ZwClose(thread_handle);
	}

	closesocket(listen_sock);
	log("Server successfully shut down...");
}