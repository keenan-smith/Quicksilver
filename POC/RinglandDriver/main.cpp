#include "stdafx.h"
#include "ntos.h"
#include "sockets.h"
#include "log.h"
#include "server.h"
#include "main.h"


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
	
	status = ObReferenceObjectByHandle(thread_handle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&thread, NULL);

	if(!NT_SUCCESS(status)) {
		log("Unable to create server thread. Status code: 0x%X.", status);
		return status;
	}
	
	driver->DriverUnload = DriverUnload;

	ZwClose(thread_handle);
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	
	shut_down_server = TRUE;
	KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(thread);
}
