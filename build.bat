@echo off
echo Building Driver Cleaner...

REM Check for Visual Studio and WDK installation
if not defined VS140COMNTOOLS (
    if not defined VS150COMNTOOLS (
        if not defined VS160COMNTOOLS (
            echo Visual Studio 2015, 2017, or 2019 not found!
            pause
            exit /b 1
        )
    )
)

REM Set build environment
if defined VS160COMNTOOLS (
    call "%VS160COMNTOOLS%\VsDevCmd.bat"
) else if defined VS150COMNTOOLS (
    call "%VS150COMNTOOLS%\VsDevCmd.bat"
) else (
    call "%VS140COMNTOOLS%\VsDevCmd.bat"
)

REM Clean previous build
if exist x64 rmdir /s /q x64
if exist Debug rmdir /s /q Debug
if exist Release rmdir /s /q Release

echo.
echo Building Release configuration...
msbuild KernelCleaner.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build completed successfully!
    echo Output files:
    if exist x64\Release\KernelCleaner.sys (
        echo   - x64\Release\KernelCleaner.sys
    )
    if exist x64\Release\KernelCleaner.inf (
        echo   - x64\Release\KernelCleaner.inf
    )
    echo.
    echo To install:
    echo   1. Enable test signing: bcdedit /set testsigning on
    echo   2. Reboot system
    echo   3. Install driver: sc create KernelCleaner binPath="path\to\KernelCleaner.sys" type=kernel
    echo   4. Start driver: sc start KernelCleaner
    echo.
) else (
    echo.
    echo Build failed with error code %ERRORLEVEL%
)

pause
