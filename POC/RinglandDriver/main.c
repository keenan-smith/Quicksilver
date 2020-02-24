#include "stdafx.h"
#include "ntos.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	DbgPrintEx(0, 0, "Test from DriverEntry");
	return 0xDEAD10CC;
}