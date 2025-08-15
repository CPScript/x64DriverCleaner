# x64 Driver Cleaner

> This tool operates at the kernel level to clean driver artifacts that remain in memory after driver unloading.

## What This Does

The driver cleaner targets three main Windows kernel data structures where driver traces persist:

1. **PiDDB Cache** - Plug and Play Driver Database cache that stores information about loaded drivers
2. **Kernel Hash Buckets** - Code Integrity hash verification buckets used by Windows Kernel Security
3. **MMU/MML Lists** - Memory Management Unit unloaded drivers list that tracks recently unloaded modules

## Use Cases

- **Security Research** - Understanding Windows kernel internals and driver loading mechanisms
- **Development Testing** - Cleaning driver traces during kernel driver development cycles
- **Forensics Analysis** - Studying how Windows maintains driver loading history
- **Educational Purposes** - Learning about Windows kernel memory management structures

## How It Works

### PiDDB Cache Cleaning
- Locates the PiDDB (Plug and Play Driver Database) lock and cache table using signature scanning
- Searches for target driver entries by name and timestamp
- Removes entries from both the AVL tree structure and linked lists
- Supports Windows 10 and Windows 11 signature variants

### Hash Bucket Cleaning  
- Finds kernel hash bucket lists used by Code Integrity (ci.dll)
- Iterates through hash bucket entries to locate target driver
- Randomizes hash values to invalidate cached integrity checks
- Compatible with Windows versions from 1903 through 22H2

### MMU/MML List Cleaning
- Accesses Memory Management unloaded drivers tracking structures
- Removes target driver entries from the MM_UNLOADED_DRIVERS array
- Adjusts timestamps and compacts the list to remove gaps
- Maintains proper resource locking during modifications

## Technical Details

### Architecture
- **Target Platform**: x64 Windows (Windows 10 1903+ through Windows 11 22H2+)
- **Language**: C with Windows Driver Kit (WDK) dependencies
- **Mode**: Kernel mode driver
- **Memory Safety**: Uses proper resource locking and exception handling

### Pattern Matching
The driver uses signature-based pattern matching to locate kernel structures across different Windows versions:
- Supports version-specific patterns for Windows 10 and 11
- Falls back between signature variants for compatibility
- Uses relative address resolution for position-independent code

### Security Considerations
- Requires Administrator privileges for installation
- Modifies critical kernel data structures
- Should only be used in controlled environments
- Intended for research and educational purposes only

## Installation

1. Compile the driver using Windows Driver Kit (WDK)
2. Sign the driver or enable test signing mode
3. Install using `sc create` or driver loading utilities
4. Configure target drivers in the source code before compilation

## Configuration

Modify the target driver list in `main.c`:

```c
CleanDriverTraces(L"target_driver.sys", 0x12345678);
```

Where the second parameter is the driver's timestamp from its PE header.

## Compatibility

### Supported Windows Versions
- Windows 10 1903, 1909, 2004, 20H2, 21H1, 21H2, 22H2
- Windows 11 21H2, 22H2, 23H2
- Both x64 architectures

### Updated Signatures
The modernized version includes updated pattern signatures for:
- Windows 11 23H2 PiDDB structures
- Latest Code Integrity hash bucket layouts
- Current Memory Management structures

## Building

Requirements:
- Visual Studio 2019/2022
- Windows Driver Kit (WDK) 10.0.22000+
- Windows SDK 10.0.22000+

Build steps:
```cmd
msbuild KernelDriverCleaner.sln /p:Configuration=Release /p:Platform=x64
```

## License

**CC0 1.0 Universal**
