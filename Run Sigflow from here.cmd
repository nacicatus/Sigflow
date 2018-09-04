@echo off
set /p name=File:
set /p options=Options:
call sigflow.cmd -f %name% %options% -F "!headers['CSeq'].include?('OPTIONS')"

SET _result=%name:"=%
IF EXIST "%~dps0%_result%.html" start iexplore %~dps0%_result%.html
pause