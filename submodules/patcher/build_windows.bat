@echo off
setlocal
cd /d "%~dp0"
where x86_64-w64-mingw32-gcc >nul 2>&1
if errorlevel 1 (
    echo ERROR: MinGW-w64 gcc not on PATH. No Windows binary was built.
    exit /b 1
)
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iinclude -o patch_abl_safe.exe src\patch_abl.c src\patchs\core.c src\patchs\oplus\forceenablefastboot.c src\patchs\oplus\warning.c src\arm64_inst\utils.c src\arm64_inst\arm64_inst_decoder.c
if errorlevel 1 (
    echo ERROR: compiler failed.
    exit /b 1
)
echo Built patch_abl_safe.exe for offline use. Output is NOT flash-verified.
endlocal
