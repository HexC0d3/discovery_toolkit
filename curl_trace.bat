@echo off
:: ============================================================
::  curl_trace.bat
::  Uses: curl --trace-time --trace-ascii
::  INPUT : webapps.txt  (same folder)
::  OUTPUT: reachable_curl_webapps_OUTPUT.txt  (trace report)
::          reachable_curl_webapps_OUTPUT.csv   (summary)
:: ============================================================

setlocal enabledelayedexpansion

cd /d "%~dp0"

set "INPUT=webapps.txt"
set "OUTPUT=reachable_curl_webapps_OUTPUT.txt"
set "CSV=reachable_curl_webapps_OUTPUT.csv"
set "TMPTRACE=%TEMP%\curl_trace_%RANDOM%.txt"
set "TMPCODE=%TEMP%\curl_code_%RANDOM%.txt"

if not exist "%INPUT%" (
    echo [ERROR] webapps.txt not found in %CD%
    pause & exit /b 1
)

curl --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl not found.
    pause & exit /b 1
)

> "%OUTPUT%" echo Web Trace Report - %DATE% %TIME%
>> "%OUTPUT%" echo.
> "%CSV%" echo URL,Status,Response Code

set /a IDX=0

for /f "usebackq tokens=* delims=" %%U in ("%INPUT%") do (
    set "URL=%%U"
    if not "!URL!"=="" (
        set "FC=!URL:~0,1!"
        if not "!FC!"=="#" (
            set /a IDX+=1
            echo [!IDX!] Tracing !URL! ...
            call :TRACE "!URL!"
            echo   ^> Status: !STATUS!  Response Code: !RCODE!
            >> "%CSV%" echo !URL!,!STATUS!,!RCODE!
            >> "%OUTPUT%" echo ============================================================
            >> "%OUTPUT%" echo === !URL! ===
            >> "%OUTPUT%" echo ============================================================
            >> "%OUTPUT%" echo.
            if exist "%TMPTRACE%" (
                >> "%OUTPUT%" type "%TMPTRACE%"
                del "%TMPTRACE%" 2>nul
            ) else (
                >> "%OUTPUT%" echo [no trace output]
            )
            >> "%OUTPUT%" echo.
        )
    )
)

>> "%OUTPUT%" echo ============================================================
>> "%OUTPUT%" echo END OF REPORT  [%IDX% URLs traced]
>> "%OUTPUT%" echo ============================================================

echo.
echo Done! %IDX% URLs traced.
echo Trace : %CD%\%OUTPUT%
echo CSV   : %CD%\%CSV%
echo.
pause
endlocal
exit /b 0

:: ============================================================
:: Subroutine :TRACE
:: Runs curl, sets STATUS and RCODE
:: ============================================================
:TRACE
set "STATUS=not reachable"
set "RCODE=Null"

curl --trace-time --trace-ascii "%TMPTRACE%" -sk -o nul -w "%%{http_code}" --connect-timeout 10 --max-time 15 %~1 > "%TMPCODE%" 2>nul
set "CURL_RC=%errorlevel%"

set "HTTPCODE="
set /p HTTPCODE= < "%TMPCODE%"
del "%TMPCODE%" 2>nul

:: TLS errors - server reachable but cert issue
if "%CURL_RC%"=="35" set "STATUS=live" & goto :EOF
if "%CURL_RC%"=="51" set "STATUS=live" & goto :EOF
if "%CURL_RC%"=="58" set "STATUS=live" & goto :EOF
if "%CURL_RC%"=="60" set "STATUS=live" & goto :EOF

:: Only live if curl succeeded AND got a real HTTP code
if not "%CURL_RC%"=="0" goto :EOF
if "%HTTPCODE%"=="000" goto :EOF
if "%HTTPCODE%"==""    goto :EOF

set "STATUS=live"
set "RCODE=%HTTPCODE%"
goto :EOF
