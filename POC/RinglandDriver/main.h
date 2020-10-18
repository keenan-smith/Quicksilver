#pragma once
#include <ntddk.h>
#include <wdm.h>


VOID DriverUnload(IN PDRIVER_OBJECT obj);

PETHREAD* thread;
