@echo off
setlocal
cd /d "%~dp0"
where cargo >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Rust/Cargo not found. Install from https://rustup.rs/
    pause
    exit /b 1
)
echo [CHECK] cargo check --workspace --all-targets
cargo check --workspace --all-targets
if errorlevel 1 goto failed
echo [TEST] cargo test --workspace
cargo test --workspace
if errorlevel 1 goto failed
echo [OK] Workspace checks and tests passed.
pause
exit /b 0
:failed
echo [FAIL] Cargo build or tests failed. Copy this window's output to the chat.
pause
exit /b 1
