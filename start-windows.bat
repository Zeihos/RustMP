@echo off
setlocal
cd /d "%~dp0"
where cargo >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Cargo was not found. Install Rust from https://rustup.rs/
    pause
    exit /b 1
)
echo [INFO] Starting Rust SA-MP networking alpha. This is not yet a playable server.
cargo run --release -p omp-server -- --config config.json
if errorlevel 1 (
    echo [ERROR] Server startup failed.
    pause
    exit /b 1
)
endlocal
