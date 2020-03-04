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

NTSTATUS ZwVirtualProtect(
    UINT32 process_id,
    UINT64 address,
    UINT64 size,
    UINT32 protect
) {
    PEPROCESS proc = nullptr;
    ULONG oldProt;
    KAPC_STATE apc;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(process_id), &proc)))
    {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(proc, &apc);
    NTSTATUS status = ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID*)&address, (PSIZE_T)&size, protect, &oldProt);
    KeUnstackDetachProcess(&apc);
    if (proc)
        ObDereferenceObject(proc);
    return status;
}

NTSTATUS ZwVirtualAlloc(
    UINT32 process_id,
    UINT64 &size,
    UINT32 allocation_type,
    UINT32 protect,
    UINT64 &address
) {
    PEPROCESS proc = nullptr;
    ULONG oldProt;
    KAPC_STATE apc;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(process_id), &proc)))
    {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(proc, &apc);
    NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&address, 0, (PSIZE_T)&size, allocation_type, protect);
    KeUnstackDetachProcess(&apc);
    if (proc)
        ObDereferenceObject(proc);
    return status;
}

UINT64 ZwGetModuleHandle(
    UINT32 process_id,
    const char* module_name
) {
    PEPROCESS process = nullptr;
    KAPC_STATE apc;
    NTSTATUS  status = PsLookupProcessByProcessId(HANDLE(process_id), &process);
    UINT64 base = 0;

    if (!NT_SUCCESS(status))
        return 0;

    KeStackAttachProcess(process, &apc);

    PPEB peb = PsGetProcessPeb(process);
    if (!peb)
        goto end;

    if (!peb->Ldr || !peb->Ldr->Initialized)
        goto end;

    ANSI_STRING as;
    UNICODE_STRING module_name_unicode;
    RtlInitAnsiString(&as, module_name);
    RtlAnsiStringToUnicodeString(&module_name_unicode, &as, TRUE);
    for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
        list != &peb->Ldr->InLoadOrderModuleList;
        list = list->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        //log("Checking module: Base name %wZ, Full name %wZ", entry->BaseDllName, entry->FullDllName);
        if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
            base = (UINT64)entry->DllBase;
            goto end;
        }
    }

end:
    KeUnstackDetachProcess(&apc);
    if (process)
        ObDereferenceObject(process);
    return base;
}

NTSTATUS ZwCreateRemoteThread(
    UINT32 process_id,
    UINT64 entry_point,
    UINT64 base_address
){
    PEPROCESS proc = nullptr;
    KAPC_STATE apc;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(process_id), &proc)))
    {
        return STATUS_INVALID_CID;
    }

    KeStackAttachProcess(proc, &apc);

    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES ob = { 0 };
    InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwCreateThreadEx(
        &hThread, THREAD_QUERY_LIMITED_INFORMATION, &ob,
        ZwCurrentProcess(), (PVOID)entry_point, (PVOID)base_address, 0x00000004,
        0, 0x1000, 0x100000, NULL
    );

    ZwClose(hThread);
    KeUnstackDetachProcess(&apc);
    if (proc)
        ObDereferenceObject(proc);

	//PVOID pBase = UtilKernelBase(&size);
	log("NtCreateThread: 0x%X", (ULONG_PTR)GetSSDTEntry(dynData.NtCreateThdIndex));

    return status;
}