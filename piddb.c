#include "main.h"

// Windows 10 signature
static UCHAR PiDDBLockPattern_Win10[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";
static CHAR PiDDBLockMask_Win10[] = "xxxxxx????xxxxx????xxx????xxxxx????x????xxx";

// Windows 11 signature  
static UCHAR PiDDBLockPattern_Win11[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";
static CHAR PiDDBLockMask_Win11[] = "xxx????xxxxx????xxx????x????x";

// Updated Windows 11 23H2 signature
static UCHAR PiDDBLockPattern_Win11_23H2[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x75\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x0D";
static CHAR PiDDBLockMask_Win11_23H2[] = "xxx????xxxx?xxx????x????xxx";

// Cache table signature (common across versions)
static UCHAR PiDDBCachePattern[] = "\x66\x03\xD2\x48\x8D\x0D";
static CHAR PiDDBCacheMask[] = "xxxxxx";

BOOLEAN LocatePiDDBStructures(_Out_ PERESOURCE* Lock, _Out_ PRTL_AVL_TABLE* Table) {
    PVOID lockPtr = NULL;
    PVOID tablePtr = NULL;
    PVOID ntosBase;
    
    ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        LOG("Failed to get ntoskrnl.exe base");
        return FALSE;
    }
    
    // Try Windows 11 23H2 signature first
    lockPtr = FindPatternInSection(ntosBase, "PAGE", PiDDBLockPattern_Win11_23H2, PiDDBLockMask_Win11_23H2);
    if (lockPtr) {
        lockPtr = (PUCHAR)lockPtr + 14;
        LOG("Found Windows 11 23H2 PiDDB signature");
    } else {
        // Try Windows 10 signature
        lockPtr = FindPatternInSection(ntosBase, "PAGE", PiDDBLockPattern_Win10, PiDDBLockMask_Win10);
        if (lockPtr) {
            lockPtr = (PUCHAR)lockPtr + 28;
            LOG("Found Windows 10 PiDDB signature");
        } else {
            // Try Windows 11 signature
            lockPtr = FindPatternInSection(ntosBase, "PAGE", PiDDBLockPattern_Win11, PiDDBLockMask_Win11);
            if (lockPtr) {
                lockPtr = (PUCHAR)lockPtr + 16;
                LOG("Found Windows 11 PiDDB signature");
            } else {
                LOG("Could not find PiDDB lock signature");
                return FALSE;
            }
        }
    }
    
    tablePtr = FindPatternInSection(ntosBase, "PAGE", PiDDBCachePattern, PiDDBCacheMask);
    if (!tablePtr) {
        LOG("Could not find PiDDB cache table signature");
        return FALSE;
    }
    
    tablePtr = (PUCHAR)tablePtr + 3;
    
    *Lock = (PERESOURCE)ResolveRelativeAddress(lockPtr, 3, 7);
    *Table = (PRTL_AVL_TABLE)ResolveRelativeAddress(tablePtr, 3, 7);
    
    if (!*Lock || !*Table) {
        LOG("Failed to resolve PiDDB addresses");
        return FALSE;
    }
    
    return TRUE;
}

BOOLEAN CleanPiDDBCache(_In_ PUNICODE_STRING DriverName, _In_ ULONG TimeDateStamp) {
    PERESOURCE piDDBLock = NULL;
    PRTL_AVL_TABLE piDDBTable = NULL;
    PIDDB_CACHE_ENTRY lookupEntry = {0};
    PPIDDB_CACHE_ENTRY foundEntry = NULL;
    BOOLEAN result = FALSE;
    
    if (!LocatePiDDBStructures(&piDDBLock, &piDDBTable)) {
        return FALSE;
    }
    
    lookupEntry.DriverName = *DriverName;
    lookupEntry.TimeDateStamp = TimeDateStamp;
    
    __try {
        ExAcquireResourceExclusiveLite(piDDBLock, TRUE);
        
        foundEntry = (PPIDDB_CACHE_ENTRY)RtlLookupElementGenericTableAvl(piDDBTable, &lookupEntry);
        if (!foundEntry) {
            LOG("PiDDB entry not found for driver: %wZ", DriverName);
            goto cleanup;
        }
        
        RemoveEntryList(&foundEntry->List);
        
        if (!RtlDeleteElementGenericTableAvl(piDDBTable, foundEntry)) {
            LOG("Failed to delete PiDDB AVL table entry");
            goto cleanup;
        }
        
        result = TRUE;
        LOG("Successfully cleaned PiDDB entry for: %wZ", DriverName);
        
    cleanup:
        ExReleaseResourceLite(piDDBLock);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception occurred while cleaning PiDDB cache");
        result = FALSE;
    }
    
    return result;
}
