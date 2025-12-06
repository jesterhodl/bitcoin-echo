@echo off
REM Bitcoin Echo — Windows Build Script
REM Build once. Build right. Stop.

setlocal

set CC=cl
set CFLAGS=/std:c11 /W4 /O2
set TARGET=echo.exe

REM Source files (will be populated as implementation progresses)
set SRCS=src\main.c

echo Building Bitcoin Echo...
%CC% %CFLAGS% /Fe:%TARGET% %SRCS%

if %ERRORLEVEL% EQU 0 (
    echo Build successful: %TARGET%
) else (
    echo Build failed
    exit /b 1
)

endlocal
