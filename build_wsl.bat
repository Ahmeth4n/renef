@echo off

:: Check WSL
where wsl >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] WSL not found. Install: wsl --install
    exit /b 1
)

:: Find project root: try script location first, then current directory
if exist "%~dp0CMakeLists.txt" (
    if exist "%~dp0src\librenef" (
        pushd "%~dp0"
    ) else (
        echo [ERROR] CMakeLists.txt found in %~dp0 but src/ folder is missing.
        echo         Make sure you have the full project. Run: git clone https://github.com/ahmeth4n/renef.git
        exit /b 1
    )
) else if exist "%CD%\CMakeLists.txt" (
    if exist "%CD%\src\librenef" (
        pushd "%CD%"
    ) else (
        echo [ERROR] CMakeLists.txt found but src/ folder is missing.
        echo         Make sure you have the full project. Run: git clone https://github.com/ahmeth4n/renef.git
        exit /b 1
    )
) else (
    echo [ERROR] CMakeLists.txt not found.
    echo         cd into the renef project folder and run again.
    echo         Or clone: git clone https://github.com/ahmeth4n/renef.git
    exit /b 1
)

:: WSL inherits the working directory from cmd.exe
:: Fix CRLF line endings if git converted them on Windows
wsl sed -i 's/\r$//' build.sh
wsl bash build.sh
set "RC=%errorlevel%"

popd
exit /b %RC%
