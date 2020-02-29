#include "globals.h"
#include "krnlhelper.h"
#include "log.h"

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

bool should_server_be_running = true;
bool shut_down_server = false;

void MakeDynamicData() {
    NTSTATUS status = STATUS_SUCCESS;
    status = InitDynamicData(&dynData);

    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_NOT_SUPPORTED)
            log("Unsupported OS version. Aborting.");
    }
}

NTSTATUS ZwCreateRemoteThread
(
    UINT32 process_id,
    UINT64 entry_point,
    UINT64 base_address
)
{
    PEPROCESS proc = nullptr;
    KAPC_STATE apc;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(process_id), &proc)))
    {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(proc, &apc);


    ZwCreateThreadEx()

	//PVOID pBase = UtilKernelBase(&size);
	log("NtCreateThread: 0x%X", (ULONG_PTR)GetSSDTEntry(dynData.NtCreateThdIndex));
}