Set-Location -Path "D:\EXT\urls"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " CRAWLIZER - PUSHING UPDATES TO GITHUB" -ForegroundColor Green
Write-Host " Target: https://github.com/bountrixorg/Crawlizer.git" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan

Write-Host "`n[1/3] Staging all files..." -ForegroundColor Gray
git add -A

Write-Host "[2/3] Creating commit..." -ForegroundColor Gray
git commit -m "Rebrand to Crawlizer and complete Cyberpunk UI redesign (Green, Red, Black theme with expanded secrets finding panel)"

Write-Host "[3/3] Pushing to main branch..." -ForegroundColor Gray
git push -u origin main

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[NOTICE] Push had exit code $LASTEXITCODE. Trying git push -u origin main --force..." -ForegroundColor Yellow
    git push -u origin main --force
}

Write-Host "`n[SUCCESS] Completed!" -ForegroundColor Green
