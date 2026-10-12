@echo off
setlocal
cd /d "D:\EXT\urls"

echo ========================================================
echo  CRAWLIZER - PUSHING UPDATES TO GITHUB
echo  Target: https://github.com/bountrixorg/Crawlizer.git
echo ========================================================
echo.

echo [1/3] Staging all files...
git add -A

echo [2/3] Creating commit...
git commit -m "Rebrand to Crawlizer and complete Cyberpunk UI redesign (Green, Red, Black theme with expanded secrets finding panel)"

echo [3/3] Pushing to main branch...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Push completed successfully to https://github.com/bountrixorg/Crawlizer.git!
) else (
    echo.
    echo [NOTICE] If the remote repository is empty or requires force initialization, trying git push -u origin main --force...
    git push -u origin main --force
)

echo.
pause
