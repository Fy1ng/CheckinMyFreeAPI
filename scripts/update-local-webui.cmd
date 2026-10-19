@echo off
setlocal
set "update_test_root=%~1"
set "update_repository_root=%~2"
if "%update_repository_root%"=="" set "update_repository_root=%~dp0.."
echo Starting local WebUI update...
if "%update_test_root%"=="" (
    echo Usage: update-local-webui.cmd "TEST_DATA_DIRECTORY" ["REPOSITORY_DIRECTORY"]
    echo No service was stopped or started.
    pause
    exit /b 2
)
echo Test directory: "%update_test_root%"
echo Update log: "%update_test_root%\update.log"
powershell.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0restart_local_webui.ps1" -TestRoot "%update_test_root%" -RepositoryRoot "%update_repository_root%"
set "update_result=%errorlevel%"
echo.
if "%update_result%"=="0" (
    echo Update completed. Refresh the WebUI.
) else (
    echo Update failed with exit code %update_result%.
    echo Review the error above and "%update_test_root%\update.log".
)
pause
exit /b %update_result%
