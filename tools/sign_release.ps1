param([Parameter(Mandatory=$true)][string]$Target)
$ErrorActionPreference='Stop'
$projectPath=Split-Path -Parent $PSScriptRoot
$signToolPath='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$privatePfx=Join-Path $projectPath '.release-keys\authenticode.pfx'
$signPassword=[System.IO.File]::ReadAllText((Join-Path $projectPath '.release-keys\authenticode.password'))
& $signToolPath sign /fd SHA256 /f $privatePfx /p $signPassword $Target
if($LASTEXITCODE -ne 0){throw 'Authenticode 签名失败'}
