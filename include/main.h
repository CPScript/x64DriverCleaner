#pragma once

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <wdm.h>

#define DRIVER_TAG 'kClN'
#define MM_UNLOADED_DRIVERS_SIZE 50

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID ModuleStart;
    PVOID ModuleEnd;
    ULONG64 UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

typedef struct _PIDDB_CACHE_ENTRY {
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    CHAR _Reserved[16];
} PIDDB_CACHE_ENTRY, *PPIDDB_CACHE_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
    _In_ PVOID Base
);

// Function declarations
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

PVOID GetKernelModuleBase(_In_ PCSTR ModuleName);
PVOID FindPatternInSection(_In_ PVOID ModuleBase, _In_ PCSTR SectionName, _In_ PUCHAR Pattern, _In_ PCSTR Mask);
PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);

BOOLEAN CleanPiDDBCache(_In_ PUNICODE_STRING DriverName, _In_ ULONG TimeDateStamp);
BOOLEAN CleanHashBuckets(_In_ PUNICODE_STRING DriverName);
BOOLEAN CleanMmUnloadedDrivers(_In_ PUNICODE_STRING DriverName);

VOID CleanDriverTraces(_In_ PCWSTR DriverName, _In_ ULONG TimeDateStamp);

// Logging macro
#define LOG(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[KernelCleaner] " format "\n", ##__VA_ARGS__)
