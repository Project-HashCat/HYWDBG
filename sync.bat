@echo off
chcp 65001 >nul

set "SRC=L:\ProjectHashCat\HYWDbg"
set "DST=C:\HYWDbg"

if not exist "%DST%" mkdir "%DST%"

echo [HYWDbg Sync] %SRC%  --^>  %DST%
echo [HYWDbg Sync] Ctrl+C 停止
echo.

:loop
robocopy "%SRC%" "%DST%" /E /FFT /Z /XA:H /R:1 /W:1 /MT:16 /XD target .git .vs node_modules dist build out .idea .vscode /XF *.pdb *.ilk *.obj *.exe *.dll *.lib *.exp *.tmp *.tlog

timeout /t 2 /nobreak >nul
goto loop