param([switch]$RefreshBaseline, [string]$BuildPython)
$ErrorActionPreference = 'Stop'
$projectPath = $PSScriptRoot
$env:PYINSTALLER_CONFIG_DIR = Join-Path $projectPath 'build\pyinstaller-cache'
$pythonPath = if ($BuildPython) { (Resolve-Path -LiteralPath $BuildPython).Path } else { Join-Path $projectPath '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $pythonPath)) { throw '先创建 .venv 并安装 requirements-build.txt。' }
$pythonBasePath = (& $pythonPath -c 'import sys; print(sys.base_prefix)').Trim()
# Ambient tool PATH can contain an unrelated ICU DLL (e.g. Poppler) with the same
# filename as Windows ICU. Keep dependency resolution confined to the build runtime.
$env:PATH = ((Join-Path $projectPath '.venv\Scripts'), $pythonBasePath,
    (Join-Path $pythonBasePath 'DLLs'), (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot) -join ';'
Set-Location -LiteralPath $projectPath
if ($RefreshBaseline) {
    & $pythonPath tools/build_baseline.py
    if ($LASTEXITCODE -ne 0) { throw '生成可信基线失败。' }
}
& $pythonPath -m tests.test_security
if ($LASTEXITCODE -ne 0) { throw '安全测试未通过。' }
& $pythonPath tools/test_native_uninstall.py
if($LASTEXITCODE -ne 0){throw '原生卸载回归未通过。'}
& $pythonPath tools/make_icon.py
if ($LASTEXITCODE -ne 0) { throw '生成图标失败。' }
& $pythonPath tools/collect_licenses.py
if ($LASTEXITCODE -ne 0) { throw '收集许可证失败。' }
& $pythonPath tools/create_signer.py
if ($LASTEXITCODE -ne 0) { throw '生成签名证书失败。' }
& $pythonPath tools/build_exe.py
if ($LASTEXITCODE -ne 0) { throw 'EXE 打包失败。' }
$csharpCompiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $pythonPath tools/build_uninstaller.py
if($LASTEXITCODE -ne 0){throw '卸载程序构建失败。'}
& $csharpCompiler /nologo /target:exe /platform:x64 /reference:Microsoft.CSharp.dll /reference:System.Web.Extensions.dll "/win32manifest:$projectPath\tools\admin.manifest" "/out:$projectPath\dist\SteamSafe\SteamSafeTaskHelper.exe" "$projectPath\tools\TaskHelper.cs" "$projectPath\tools\UninstallMaintenance.cs" "$projectPath\build\SetupCommon.generated.cs"
if($LASTEXITCODE -ne 0){throw '计划任务组件构建失败。'}
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'dist\SteamSafe\SteamSafe.exe')
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'dist\SteamSafe\SteamSafeTaskHelper.exe')
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'dist\SteamSafe\Uninstall.exe')
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'dist\SteamSafe-Uninstall-Repair.exe')
Copy-Item -LiteralPath README.md -Destination dist/使用说明-v0.1.2.md -Force
Copy-Item -LiteralPath README.md -Destination dist/SteamSafe/使用说明.md -Force
Copy-Item -LiteralPath THIRD-PARTY-NOTICES.md -Destination dist/SteamSafe/THIRD-PARTY-NOTICES.md -Force
Copy-Item -LiteralPath licenses -Destination dist/SteamSafe/licenses -Recurse -Force
& $pythonPath tools/seal_release.py
if($LASTEXITCODE -ne 0){throw '发行文件清单签署失败。'}
& $pythonPath tools/package_installer.py
if($LASTEXITCODE -ne 0){throw '管理员安装器构建失败。'}
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'dist\SteamSafe-v0.1.2.3-Beta-Setup.exe')
& $pythonPath tools/prepare_setup_qa.py
if($LASTEXITCODE -ne 0){throw '安装向导诊断副本准备失败。'}
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'build\setup-qa\Setup.exe')
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'build\setup-qa\Uninstall.exe')
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'build\setup-qa\Repair.exe')
& $pythonPath tools/verify_setup.py
if($LASTEXITCODE -ne 0){throw '安装与卸载界面测试失败。'}
& $pythonPath tools/prepare_diagnostic.py
if($LASTEXITCODE -ne 0){throw '同代码诊断副本准备失败。'}
& tools/sign_release.ps1 -Target (Join-Path $projectPath 'build\qa-release\SteamSafe.exe')
& $pythonPath tools/seal_release.py (Join-Path $projectPath 'build\qa-release')
& $pythonPath tools/verify_release.py
if ($LASTEXITCODE -ne 0) { throw '打包后的自测或界面验证失败，请勿分发。' }
Write-Host '自签名管理员安装版生成完成，自测与界面启动验证通过。'
