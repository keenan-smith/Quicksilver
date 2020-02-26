#include "server.h"

SOCKET make_listen_sock() {
	SOCKADDR_IN addr{};

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(25560);

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

void NTAPI thread_connection(void*) {

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

	log("Listening on port 25560.");

	while (true) {
		sockaddr  socket_addr{};
		socklen_t socket_length{};

		int client_connection = accept(listen_sock, &socket_addr, &socket_length);
		if (client_connection == INVALID_SOCKET) {
			log("Unable to accept client connection.");
			break;
		}

		HANDLE thread_handle = nullptr;


	}

}