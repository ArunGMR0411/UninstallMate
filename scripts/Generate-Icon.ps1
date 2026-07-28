[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class IconNativeMethods {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr handle);
}
'@

$root = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $root 'src\UninstallMate\Assets\UninstallMate.ico'
$bitmap = [System.Drawing.Bitmap]::new(64, 64)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::FromArgb(11, 16, 32))
$teal = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(103, 232, 195))
$dark = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(7, 18, 15))
$graphics.FillEllipse($teal, 5, 5, 54, 54)
$font = [System.Drawing.Font]::new('Segoe UI', 32, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$format = [System.Drawing.StringFormat]::new()
$format.Alignment = [System.Drawing.StringAlignment]::Center
$format.LineAlignment = [System.Drawing.StringAlignment]::Center
$graphics.DrawString('U', $font, $dark, [System.Drawing.RectangleF]::new(5, 3, 54, 54), $format)
$handle = $bitmap.GetHicon()
try {
    $icon = [System.Drawing.Icon]::FromHandle($handle)
    $stream = [System.IO.File]::Create($destination)
    try { $icon.Save($stream) } finally { $stream.Dispose(); $icon.Dispose() }
} finally {
    [IconNativeMethods]::DestroyIcon($handle) | Out-Null
    $format.Dispose(); $font.Dispose(); $dark.Dispose(); $teal.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
Write-Host "Generated $destination"
