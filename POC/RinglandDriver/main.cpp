#include "stdafx.h"
#include "ntos.h"
#include "sockets.h"
#include "log.h"



NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	log("DriverEntry initialization...");
	return 0xDEAD10CC;
}