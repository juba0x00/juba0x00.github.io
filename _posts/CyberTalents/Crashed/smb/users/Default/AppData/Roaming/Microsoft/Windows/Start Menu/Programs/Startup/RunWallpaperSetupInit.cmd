@Echo Off
REM Render instance information on current wallpaper if this is the wallpaper was never changed by user.
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper -Initial" & REM DELETEME
type "%~f0" | findstr /v DELETEME > "%~dp0RunWallpaperSetup.cmd"
DEL /Q /F "%~f0" & REM DELETEME
GOTO :EOF & REM DELETEME
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper"