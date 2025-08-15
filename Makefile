# Build configuration
TARGET_NAME = KernelCleaner
TARGET_TYPE = DRIVER
DRIVERTYPE = WDM

# Source files
SOURCES = main.c \
          piddb.c \
          hash.c \
          mmu.c

# Include directories
INCLUDES = $(DDK_INC_PATH)

# Target platform
TARGETLIBS = $(DDK_LIB_PATH)\ntoskrnl.lib \
             $(DDK_LIB_PATH)\hal.lib \
             $(DDK_LIB_PATH)\wdm.lib

# Build settings
MSC_WARNING_LEVEL = /W4
C_DEFINES = $(C_DEFINES) -D_X86_=1 -Di386=1 -DSTD_CALL -DCONDITION_HANDLING=1 -DNT_UP=1 -DNT_INST=0 -DWIN32=100 -D_NT1X_=100 -DWINNT=1 -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -D_WIN32_IE=0x0800 -DWIN32_LEAN_AND_MEAN=1 -DDEVL=1 -D__BUILDMACHINE__=WinDDK -DFPO=0

# Enable additional warnings and optimizations
MSC_OPTIMIZATION = /O2
USE_MSVCRT = 1
