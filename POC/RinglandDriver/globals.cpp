#include "globals.h"
#include "ntos.h"

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

bool should_server_be_running = true;
bool shut_down_server = false;

#pragma warning(push)
unsigned long long kernel_create_remote_thread(unsigned int pid, unsigned long long start, unsigned long long arg) {
	PEPROCESS dest_proc = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(pid), &dest_proc)))
	{
		return unsigned long long(STATUS_INVALID_CID);
	}

	KeAttachProcess(dest_proc);

	HANDLE ThreadHandle = nullptr;
	//ZwCreateThreadEx(&ThreadHandle, GENERIC_ALL, NULL, NtCurrentProcess(), (PVOID)start, (PVOID)arg, FALSE, NULL, NULL, NULL, NULL);

	//CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)start, (LPVOID)arg, 0, NULL);

	return 0xA11C13A8;
}
#pragma warning(pop)