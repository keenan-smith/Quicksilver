#include "stdafx.h"
#include "ntos.h"

#define drv L"\\Driver\\ring0inj"

PDEVICE_OBJECT driver_object;
UNICODE_STRING dev, dos;

NTSTATUS initialize(PDRIVER_OBJECT driver, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(path);

	DbgPrint("Test from DriverObject, DriverName = %wZ", &driver->DriverName);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	UNICODE_STRING drv_name;
	RtlInitUnicodeString(&drv_name, drv);
	DbgPrint("Test from DriverEntry");
	return IoCreateDriver(&drv_name, &initialize);
}