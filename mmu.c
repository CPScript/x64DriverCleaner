#include "main.h"

// MMU signatures (consistent across versions)
static UCHAR MmuPattern[] = "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9";
static CHAR MmuMask[] = "xxx????xxx";

// MML signatures
static UCHAR MmlPattern[] = "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32";
static CHAR MmlMask[] = "xx????xxx";

// Windows 11 23H2 updated MML pattern
static UCHAR MmlPattern_Win11_23H2[] = "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32\x73\x00\x48\x8B";
static CHAR MmlMask_Win11_23H2[] = "xx????xxxx?xx";

PMM_UNLOADED_DRIVER GetMmUnloadedDrivers(VOID) {
    PVOID ntosBase;
    PVOID signatureAddr;
    
    ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        return NULL;
    }
    
    signatureAddr = FindPatternInSection(ntosBase, ".text", MmuPattern, MmuMask);
    if (!signatureAddr) {
        LOG("Could not find MmUnloadedDrivers signature");
        return NULL;
    }
    
    return *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(signatureAddr, 3, 7);
}

PULONG GetMmLastUnloadedDriver(VOID) {
    PVOID ntosBase;
    PVOID signatureAddr = NULL;
    
    ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        return NULL;
    }
    
    // Try Windows 11 23H2 signature first
    signatureAddr = FindPatternInSection(ntosBase, ".text", MmlPattern_Win11_23H2, MmlMask_Win11_23H2);
    if (signatureAddr) {
        LOG("Found Windows 11 23H2 MmLastUnloadedDriver signature");
        return (PULONG)ResolveRelativeAddress(signatureAddr, 2, 6);
    }
    
    // Try standard signature
    signatureAddr = FindPatternInSection(ntosBase, ".text", MmlPattern, MmlMask);
    if (!signatureAddr) {
        LOG("Could not find MmLastUnloadedDriver signature");
        return NULL;
    }
    
    return (PULONG)ResolveRelativeAddress(signatureAddr, 2, 6);
}

BOOLEAN IsEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry) {
    return (Entry->Name.MaximumLength == 0 || 
            Entry->Name.Length == 0 || 
            Entry->Name.Buffer == NULL);
}

PERESOURCE GetPsLoadedModuleResource(VOID) {
    PVOID ntosBase;
    UNICODE_STRING routineName;
    PVOID mmGetSystemRoutine;
    PVOID (*pMmGetSystemRoutineAddress)(PUNICODE_STRING);
    
    ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        return NULL;
    }
    
    RtlInitUnicodeString(&routineName, L"MmGetSystemRoutineAddress");
    mmGetSystemRoutine = MmGetSystemRoutineAddress(&routineName);
    if (!mmGetSystemRoutine) {
        return NULL;
    }
    
    pMmGetSystemRoutineAddress = (PVOID (*)(PUNICODE_STRING))mmGetSystemRoutine;
    
    RtlInitUnicodeString(&routineName, L"PsLoadedModuleResource");
    return (PERESOURCE)pMmGetSystemRoutineAddress(&routineName);
}

ULONG GenerateRandomTime(VOID) {
    LARGE_INTEGER time;
    ULONG seed;
    
    KeQuerySystemTimePrecise(&time);
    seed = time.LowPart;
    
    return RtlRandomEx(&seed) % 10000 + 1;
}

BOOLEAN CleanMmUnloadedDrivers(_In_ PUNICODE_STRING DriverName) {
    PMM_UNLOADED_DRIVER mmUnloadedDrivers;
    PULONG mmLastUnloadedDriver;
    PERESOURCE psLoadedModuleResource;
    BOOLEAN modified = FALSE;
    BOOLEAN isFull = TRUE;
    
    mmUnloadedDrivers = GetMmUnloadedDrivers();
    mmLastUnloadedDriver = GetMmLastUnloadedDriver();
    psLoadedModuleResource = GetPsLoadedModuleResource();
    
    if (!mmUnloadedDrivers || !mmLastUnloadedDriver || !psLoadedModuleResource) {
        LOG("Failed to locate MM unloaded driver structures");
        return FALSE;
    }
    
    // Check if array is full
    for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
        if (IsEntryEmpty(&mmUnloadedDrivers[i])) {
            isFull = FALSE;
            break;
        }
    }
    
    __try {
        ExAcquireResourceExclusiveLite(psLoadedModuleResource, TRUE);
        
        for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
            PMM_UNLOADED_DRIVER entry = &mmUnloadedDrivers[i];
            
            if (IsEntryEmpty(entry)) {
                continue;
            }
            
            if (modified) {
                // Shift entries down to fill gaps
                if (i > 0) {
                    PMM_UNLOADED_DRIVER prevEntry = &mmUnloadedDrivers[i - 1];
                    RtlCopyMemory(prevEntry, entry, sizeof(MM_UNLOADED_DRIVER));
                    
                    if (i == MM_UNLOADED_DRIVERS_SIZE - 1) {
                        RtlZeroMemory(entry, sizeof(MM_UNLOADED_DRIVER));
                    }
                }
            }
            else if (RtlEqualUnicodeString(DriverName, &entry->Name, TRUE)) {
                // Found target driver - clean it
                PVOID nameBuffer = entry->Name.Buffer;
                RtlZeroMemory(entry, sizeof(MM_UNLOADED_DRIVER));
                
                if (nameBuffer) {
                    ExFreePoolWithTag(nameBuffer, 0);
                }
                
                // Update counter
                *mmLastUnloadedDriver = (isFull ? MM_UNLOADED_DRIVERS_SIZE : *mmLastUnloadedDriver) - 1;
                modified = TRUE;
                
                LOG("Found and cleaned MM unloaded driver entry: %wZ", DriverName);
            }
        }
        
        // Fix timestamps to maintain chronological order
        if (modified) {
            ULONG64 previousTime = 0;
            
            for (LONG i = MM_UNLOADED_DRIVERS_SIZE - 2; i >= 0; i--) {
                PMM_UNLOADED_DRIVER entry = &mmUnloadedDrivers[i];
                
                if (IsEntryEmpty(entry)) {
                    continue;
                }
                
                if (previousTime != 0 && entry->UnloadTime > previousTime) {
                    entry->UnloadTime = previousTime - GenerateRandomTime();
                }
                
                previousTime = entry->UnloadTime;
            }
        }
        
        ExReleaseResourceLite(psLoadedModuleResource);
        
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception occurred while cleaning MM unloaded drivers");
        ExReleaseResourceLite(psLoadedModuleResource);
        return FALSE;
    }
    
    if (!modified) {
        LOG("No MM unloaded driver entries found for: %wZ", DriverName);
    }
    
    return modified;
}
