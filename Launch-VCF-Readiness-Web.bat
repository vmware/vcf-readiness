@echo off
setlocal
pushd "%~dp0" || goto :launch_failed
if not exist "vcfr_web.py" goto :source_missing
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 goto :use_python
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 goto :use_py
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 goto :use_python3
echo Python 3.9 or newer is required. Install Python and reopen this launcher.
set "VCFR_EXIT_CODE=1"
goto :finish

:use_python
python "%~dp0vcfr_web.py" %*
set "VCFR_EXIT_CODE=%errorlevel%"
goto :finish

:use_py
py -3 "%~dp0vcfr_web.py" %*
set "VCFR_EXIT_CODE=%errorlevel%"
goto :finish

:use_python3
python3 "%~dp0vcfr_web.py" %*
set "VCFR_EXIT_CODE=%errorlevel%"
goto :finish

:source_missing
echo Extract the complete source ZIP before launching. vcfr_web.py was not found.
set "VCFR_EXIT_CODE=1"

:finish
popd
if not "%VCFR_EXIT_CODE%"=="0" (
    echo VCF Readiness could not start or exited with an error.
    if not defined CI if not "%NONINTERACTIVE%"=="1" pause
)
exit /b %VCFR_EXIT_CODE%

:launch_failed
echo Could not open the launcher directory. Extract the complete ZIP and try again.
if not defined CI if not "%NONINTERACTIVE%"=="1" pause
exit /b 1
