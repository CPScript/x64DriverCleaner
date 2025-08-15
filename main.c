#include "main.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    LOG("Driver loaded - starting cleanup operations");
    
    DriverObject->DriverUnload = DriverUnload;
    
    // Clean specific drivers
    CleanDriverTraces(L"target_driver.sys", 0x12345678);
    CleanDriverTraces(L"PROCEXP152.SYS", 0x611AB60D);
    
    LOG("Cleanup operations completed");
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    LOG("Driver unloading");
}

VOID CleanDriverTraces(_In_ PCWSTR DriverName, _In_ ULONG TimeDateStamp) {
    UNICODE_STRING uDriverName;
    RtlInitUnicodeString(&uDriverName, DriverName);
    
    LOG("Cleaning traces for driver: %wZ", &uDriverName);
    
    if (CleanPiDDBCache(&uDriverName, TimeDateStamp)) {
        LOG("PiDDB cache cleaned successfully");
    } else {
        LOG("Failed to clean PiDDB cache");
    }
    
    if (CleanHashBuckets(&uDriverName)) {
        LOG("Hash buckets cleaned successfully");
    } else {
        LOG("Failed to clean hash buckets");
    }
    
    if (CleanMmUnloadedDrivers(&uDriverName)) {
        LOG("MM unloaded drivers list cleaned successfully");
    } else {
        LOG("Failed to clean MM unloaded drivers list");
    }
}

PVOID GetKernelModuleBase(_In_ PCSTR ModuleName) {
    NTSTATUS status;
    ULONG size = 0;
    PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
    PVOID moduleBase = NULL;
    
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return NULL;
    }
    
    moduleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
    if (!moduleInfo) {
        return NULL;
    }
    
    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, size, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, DRIVER_TAG);
        return NULL;
    }
    
    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
        PCHAR currentName = (PCHAR)moduleInfo->Modules[i].FullPathName;
        if (strstr(currentName, ModuleName)) {
            moduleBase = moduleInfo->Modules[i].ImageBase;
            break;
        }
    }
    
    ExFreePoolWithTag(moduleInfo, DRIVER_TAG);
    return moduleBase;
}

BOOLEAN CheckPattern(_In_ PUCHAR Data, _In_ PUCHAR Pattern, _In_ PCSTR Mask) {
    for (; *Mask; ++Data, ++Pattern, ++Mask) {
        if (*Mask == 'x' && *Data != *Pattern) {
            return FALSE;
        }
    }
    return TRUE;
}

PVOID FindPattern(_In_ PUCHAR Base, _In_ ULONG Size, _In_ PUCHAR Pattern, _In_ PCSTR Mask) {
    ULONG patternLength = (ULONG)strlen(Mask);
    
    if (Size < patternLength) {
        return NULL;
    }
    
    for (ULONG i = 0; i <= Size - patternLength; i++) {
        if (CheckPattern(Base + i, Pattern, Mask)) {
            return Base + i;
        }
    }
    
    return NULL;
}

PVOID FindPatternInSection(_In_ PVOID ModuleBase, _In_ PCSTR SectionName, _In_ PUCHAR Pattern, _In_ PCSTR Mask) {
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER section;
    
    ntHeaders = RtlImageNtHeader(ModuleBase);
    if (!ntHeaders) {
        return NULL;
    }
    
    section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((PCHAR)section[i].Name, SectionName, 8) == 0) {
            return FindPattern(
                (PUCHAR)ModuleBase + section[i].VirtualAddress,
                section[i].Misc.VirtualSize,
                Pattern,
                Mask
            );
        }
    }
    
    return NULL;
}

PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
    ULONG_PTR instructionAddr = (ULONG_PTR)Instruction;
    LONG offset = *(PLONG)(instructionAddr + OffsetOffset);
    return (PVOID)(instructionAddr + InstructionSize + offset);
}
