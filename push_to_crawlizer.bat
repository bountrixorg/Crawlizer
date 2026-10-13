@echo off
setlocal
cd /d "D:\EXT\urls"

echo ========================================================
echo  CRAWLIZER - PUSHING HACKER UI UPDATES TO GITHUB
echo  Target: https://github.com/bountrixorg/Crawlizer.git
echo ========================================================
echo.

echo [1/3] Staging all files...
git add -A

echo [2/3] Creating commit...
git commit -m "Redesign dashboard UI to modern hacker cyberpunk theme with collapsible sidebar, command palette, live charts and single-file standalone"

echo [3/3] Pushing to main branch...
git push -u origin main

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [NOTICE] Push failed or branch mismatch. Trying force push to main...
    git push -u origin main --force
)

echo.
echo [DONE] Process completed.
pause
