#include "stdafx.h"
#include "ntos.h"
#include "sockets.h"
#include "log.h"
#include "server.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	log("DriverEntry initialization...");

	HANDLE thread_handle = nullptr;

	NTSTATUS status = PsCreateSystemThread(
		&thread_handle,
		GENERIC_ALL,
		nullptr,
		nullptr,
		nullptr,
		thread_server,
		nullptr
	);

	if (!NT_SUCCESS(status)) {
		log("Unable to create server thread. Status code: 0x%X.", status);
		return 0xDEAD10CC;
	}

	ZwClose(thread_handle);
	return 0x0;
}