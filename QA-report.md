# SteamSafe Beta v0.1.2 验证记录

日期：2026-10-10，Australia/Perth。构建与测试：Windows 11 x64 build 26200，Python 3.12.14，PyInstaller 6.22.3，Windows SDK SignTool，.NET Framework C# 编译器。

## 已完成

- 64 项模拟测试，0 失败、0 错误、0 跳过。
- 更新状态机验证：先结束 Steam 再启动更新、版本切换、三次稳定快照、完整哈希、新启动日志安装确认、旧日志不得作为新更新收据、超时不得标记完成。
- 侧载／危险配置、客服路由、复制干预、日期相关载荷、新增脚本加载、动态导入、HTML/CSS 文件事件、隔离回滚、未知文件限制、路径穿越和修改时间恢复检测。
- 自身发行文件变动、额外 DLL、发行签名不符的拒绝测试；正式目录中 260 个发行文件通过签名清单校验。
- 主程序、计划任务组件和安装器已使用自签名证书签署。固定证书指纹和 WinVerifyTrust 检查通过预期的未信任根状态，不导入系统信任库。
- 正式主 EXE 和安装器带 requireAdministrator 清单。管理员数据/安装目录和任务权限限制已实现，拒绝不可信现有目录、磁盘根、系统目录和游戏目录作为修复目标。
- 完全相同 Python 代码的诊断副本只修改 UAC 执行级别，重新签名、重新签署发行清单，在移除 Python PATH 后运行 64 项测试及离屏界面验证。截图已查看，260 个自身文件自检通过。

## 发行文件

安装器：SteamSafe-Beta-Setup.exe，43,482,896 字节。

安装器 SHA-256：`f356e0249c2e3e8705da84869c1910f6b3e130756a62549030447f7b818d8b0f`。

正式主 EXE SHA-256：`4ad0a888efebc004ee75bec89bd9d95e4bea890adcb2ea22e5e91273b4be9928`。

签名者：CN=SteamSafe Beta Self-Signed。自签名不表示公共 CA 信任或 SmartScreen 信誉。

机器记录：test-output/release-verification.json。诊断自测与截图：test-output/release-v0.1.2-qa-same-code。

## 验证边界

未在用户实际机器执行安装器，不写入 Program Files/ProgramData、不实际注册计划任务、不改变证书信任、不结束或更新用户实际 Steam。测试中的结束、启动、更新、修复使用模拟安装和替身。

正式 UAC 交互、实际管理员目录创建/任务注册、桌面令牌启动 Steam 的完整流程仍需要在受控 Windows 机器验收；不能把同代码诊断验证描述为已经完成这些实际系统操作。

没有内核驱动、PPL 或可靠内存读取阻断。Sysmon 仅使用已存在的日志，是否记录到攻击取决于配置；没有日志不会声称来源已查清。客户端修复不证明凭据没有外泄。私钥、PFX 和签名口令不进入发行或源码包。
