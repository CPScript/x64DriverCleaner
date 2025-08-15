#include "main.h"

// Windows 10 1903-21H1 signature
static UCHAR HashBucketPattern_Win10[] = "\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24";
static CHAR HashBucketMask_Win10[] = "xxx????x????xxx";

// Windows 10 22H2 signature
static UCHAR HashBucketPattern_Win10_22H2[] = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00";
static CHAR HashBucketMask_Win10_22H2[] = "xxx????x?xxxxxxx";

// Windows 11 signature
static UCHAR HashBucketPattern_Win11[] = "\x4C\x8D\x35\x00\x00\x00\x00\x48\x8B\xCE\xE8\x00\x00\x00\x00\x48\x85\xC0";
static CHAR HashBucketMask_Win11[] = "xxx????xxxx????xxx";

// Windows 11 23H2 updated signature
static UCHAR HashBucketPattern_Win11_23H2[] = "\x48\x8B\x1D\x00\x00\x00\x00\x48\x85\xDB\x74\x00\x8B\x43\x40\xA9\x00\x20\x00\x00";
static CHAR HashBucketMask_Win11_23H2[] = "xxx????xxxx?xxxxx???";

PVOID FindKernelHashBuckets(VOID) {
    PVOID ciBase;
    PVOID signatureAddr = NULL;
    
    ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        LOG("Failed to get ci.dll base address");
        return NULL;
    }
    
    // Try Windows 11 23H2 signature first
    signatureAddr = FindPatternInSection(ciBase, ".text", HashBucketPattern_Win11_23H2, HashBucketMask_Win11_23H2);
    if (signatureAddr) {
        LOG("Found Windows 11 23H2 hash bucket signature");
        return ResolveRelativeAddress(signatureAddr, 3, 7);
    }
    
    // Try Windows 11 signature
    signatureAddr = FindPatternInSection(ciBase, ".text", HashBucketPattern_Win11, HashBucketMask_Win11);
    if (signatureAddr) {
        LOG("Found Windows 11 hash bucket signature");
        return ResolveRelativeAddress(signatureAddr, 3, 7);
    }
    
    // Try Windows 10 1903-21H1 signature
    signatureAddr = FindPatternInSection(ciBase, ".text", HashBucketPattern_Win10, HashBucketMask_Win10);
    if (signatureAddr) {
        LOG("Found Windows 10 hash bucket signature");
        return ResolveRelativeAddress(signatureAddr, 3, 7);
    }
    
    // Try Windows 10 22H2 signature
    signatureAddr = FindPatternInSection(ciBase, ".text", HashBucketPattern_Win10_22H2, HashBucketMask_Win10_22H2);
    if (signatureAddr) {
        LOG("Found Windows 10 22H2 hash bucket signature");
        return ResolveRelativeAddress(signatureAddr, 3, 7);
    }
    
    LOG("Could not find kernel hash bucket signature");
    return NULL;
}

ULONG GenerateRandomHash(VOID) {
    LARGE_INTEGER time;
    ULONG seed;
    
    KeQuerySystemTimePrecise(&time);
    seed = time.LowPart;
    
    return RtlRandomEx(&seed);
}

BOOLEAN CleanHashBuckets(_In_ PUNICODE_STRING DriverName) {
    PULONGLONG hashBucketList;
    ULONG64 currentEntry;
    BOOLEAN cleaned = FALSE;
    ULONG randomValue;
    
    hashBucketList = (PULONGLONG)FindKernelHashBuckets();
    if (!hashBucketList) {
        return FALSE;
    }
    
    __try {
        currentEntry = *hashBucketList;
        
        while (currentEntry) {
            PWCHAR entryName = (PWCHAR)(currentEntry + 0x48);
            
            if (wcsstr(entryName, DriverName->Buffer)) {
                PUCHAR hashData = (PUCHAR)(currentEntry + 0x18);
                
                // Randomize the hash to invalidate it
                for (UINT i = 0; i < 20; i++) {
                    randomValue = GenerateRandomHash();
                    hashData[i] = (UCHAR)(randomValue % 256);
                }
                
                cleaned = TRUE;
                LOG("Cleaned hash bucket entry for: %wZ", DriverName);
            }
            
            currentEntry = *(PULONGLONG)currentEntry;
        }
        
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception occurred while cleaning hash buckets");
        return FALSE;
    }
    
    if (!cleaned) {
        LOG("No hash bucket entries found for: %wZ", DriverName);
    }
    
    return cleaned;
}
