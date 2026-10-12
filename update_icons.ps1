Add-Type -AssemblyName System.Drawing

$design1 = "C:\Users\mdlim\.gemini\antigravity-cli\brain\4349a3f1-2e24-48c0-9aca-69f54dd04e9d\katana_crest_badge_clean_1791838518480.jpg"
$design2 = "C:\Users\mdlim\.gemini\antigravity-cli\brain\4349a3f1-2e24-48c0-9aca-69f54dd04e9d\katana_crest_slash_dynamic_1791838535453.jpg"
$design3 = "C:\Users\mdlim\.gemini\antigravity-cli\brain\4349a3f1-2e24-48c0-9aca-69f54dd04e9d\katana_crest_icon_1791838499142.jpg"
$reference = "C:\Users\mdlim\Downloads\Cyan Wave Cannon Crest.png"

# Default to Design 1 (Clean Symmetrical Katana Wave Crest), or accept choice as argument
param([string]$choice = "1")

$sourcePath = $design1
if ($choice -eq "2") { $sourcePath = $design2 }
elseif ($choice -eq "3") { $sourcePath = $design3 }
elseif ($choice -eq "ref") { $sourcePath = $reference }

if (-not (Test-Path $sourcePath)) {
    if (Test-Path $reference) { $sourcePath = $reference }
    else {
        Write-Error "Source image not found: $sourcePath"
        exit 1
    }
}

Write-Host "Using icon source: $sourcePath" -ForegroundColor Cyan

$bmp = [System.Drawing.Bitmap]::FromFile($sourcePath)
$sizes = @(16, 32, 48, 128)
$iconsDir = Join-Path $PSScriptRoot "icons"
if (-not (Test-Path $iconsDir)) { New-Item -ItemType Directory -Path $iconsDir | Out-Null }

foreach ($s in $sizes) {
    $dest = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($dest)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # Circular mask so the extension icon renders as a sleek badge with transparent background
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddEllipse(0, 0, $s, $s)
    $g.SetClip($path)
    $g.DrawImage($bmp, 0, 0, $s, $s)
    $g.Dispose()

    $outPath = Join-Path $iconsDir "icon$s.png"
    $dest.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $dest.Dispose()
    Write-Host "Generated: $outPath ($s x $s)" -ForegroundColor Green
}

$bmp.Dispose()
Write-Host "Icon set updated successfully! Reload Katana in chrome://extensions/." -ForegroundColor Yellow
