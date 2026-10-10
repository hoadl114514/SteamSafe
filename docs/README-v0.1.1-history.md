# SteamSafe Beta v0.1.1

Windows 10/11 x64 的 Steam 正式版后台安全检查工具。EXE 包含 Python 运行时和依赖，不需要安装 Python。

## 升级与使用

1. 从托盘退出旧版本，避免继续使用旧逻辑。
2. 正常双击 `SteamSafe-v0.1.1-Beta.exe`，或解压便携包运行 `SteamSafe-v0.1.1.exe`。不要使用管理员运行。
3. 核对 Steam 安装目录。后台即时检查、结束异常进程、自动隔离／修复默认开启。
4. 首次“立即检查”，以后通过“校验并启动 Steam”使用受保护入口，检查通过后传入 `-forcesteamupdate`。
5. 需要自启时重新勾选“登录 Windows 后启动”，更新旧 EXE 路径。关闭窗口常驻托盘，从托盘菜单退出。

可信文件恢复目前支持 x64 Steam 正式版；Win32、ARM64、Steam Beta、Steam China 尚未支持。

## 即时后台检测

独立守护线程约每 0.5 秒检查进程，Windows `ReadDirectoryChangesW` 提供文件事件。网络下载在另一线程，不阻塞守护。侧载／配置先检查，命中高风险先结束 Steam，不再等待旧版的 10 秒稳定期或 3 秒延时。

参考 IsMySteamSafe 客户端规则方向，独立实现：

- Steam 根目录、bin、win64、steamui、clientui、bin/cef 及直接子目录的 `version.dll`、`versionOrg.dll`、`msacm32.drv`、`wsock32.dll`。
- `versionOrg.dll` 转发结构；额外加载入口的 Authenticode 和签名者核对。额外 Valve 签名文件只标为核对项。
- 按配置值检查更新抑制、关闭自更新、强制离线、关闭下载、下载来源覆盖。注释、明确关闭的抑制设置不误报。
- 固定客服告警返回、游戏操作提前跳转红信、隐藏地址栏、直接或局部变量指定的非官方客服路由。固定安全锁状态标为核对项。
- 只读检查 HKCU/HKLM Run/RunOnce，以及 32/64 位 IFEO Debugger、SilentProcessExit 启动劫持设置。
- 保留外部加载模块提示与可信文件校验。正常覆盖层也可能无签名，不据此删除其他软件。

脚本范围为 steamui、clientui、millennium/plugins，最多 2000 个脚本、单文件 32 MiB、总计 256 MiB。达到限制、读取失败或重解析点会报告未完成。匹配官方基线的脚本不会因模式碰巧匹配而误报；文件事件会清除缓存，即使恢复了原修改时间。

未移植原项目的全部游戏、Wallpaper、Workshop、媒体探测和完整规则数据库；不是完整 JavaScript 解释器或数据流分析器。

## 检出之后

1. 高风险客户端证据或稳定复核的同版本文件变化：立即结束实际路径属于所选安装的 Steam 进程并弹窗警告。
2. 工作线程处理修复；修复期间再次启动 Steam 会被再次结束。
3. 指定高风险侧载文件先备份再移除，只允许上述敏感目录中的四类加载文件，不删除游戏目录同名 MOD。
4. `steam.cfg` 备份后只移除命中的危险设置行，保留其他设置、注释、编码和换行。
5. 修改的程序及受覆盖界面文件从对应版本的已验证官方组件恢复。无可信原版的脚本、注册表设置和外部模块只报告并维持拦截，不猜测删除。
6. 复查、警告用户，不自动重启 Steam。

文件变化、备份错误、路径越界、重解析点、Steam 未退出或无权限写入会拒绝覆盖。修复失败继续拦截并报告。手动处理后由文件事件或复查解除拦截，未解决项目约 60 秒重试以免重复警告。

高风险规则可能识别到主动安装的客户端插件；严格模式会隔离非 Valve 客户端加载器。额外 Valve 签名文件和弱语义信号不自动删除。

## 可信基线与更新

维护工具从官方 HTTPS CDN 获取清单，验证组件 ZIP 大小和 SHA-256，计算包内文件哈希，再用维护者 Ed25519 签名。公钥编入 EXE，私钥不分发。

本版覆盖 Steam `1788652215` 的 **444 个程序／界面文件**，包括原有 98 个 EXE/DLL 和 steamui_websrc_all 中的受支持 JS/CSS/HTML。最新版本与安装版本不同不代表篡改。

联网只请求固定官方 HTTPS CDN，使用 certifi 验证 TLS，拒绝非官方重定向。用户文件哈希、本地 manifest、下载地址配置不作为可信来源。新版本首次验证可能下载组件；正确缓存可复用。断网使用匹配签名基线或当前会话已经验证的基线。

尚未实现 Valve kvsign2 独立验签；动态来源信任基于官方 HTTPS。维护者签名不是 Valve 签名，也不是 EXE 的 Windows 代码签名。

存在待安装更新时，单纯文件哈希变化延后确认，避免回退正常更新；侧载、危险配置、客服路由等语义证据仍会处理。

## 边界

用户态程序只能在发现进程／异常后迅速结束，不能保证任意入口启动的恶意代码尚未执行。扫描、硬盘和进程权限影响检测时间。受保护入口提供执行前检查，仍存在检查与执行之间的竞态。

没有驱动、PPL、防注入阻断、内存完整性或完整 IPC 检查，无法保证发现无文件注入、手动映射或管理员／内核攻击。不会统一禁止正常游戏通信。

自动修复使用当前用户权限，无权写入时保持拦截并告警，不自行提权。Beta 拒绝管理员常驻，避免把用户可修改数据目录变成提权通道。

## 数据与回滚

默认 `%LOCALAPPDATA%\SteamSafeBeta`：settings.json 为设置，last-report.json 为结果，last-incident.json 为触发证据，sentinel.log 为轮转日志，packages 为缓存，quarantine 为隔离和修复记录。

隔离目录 old 保存原文件，journal.json 记录原、新 SHA-256 及状态。“回滚最近修复”需要 Steam 退出并确认，可能恢复危险文件；后台重新发现后可能再次隔离。取证时先退出本软件。

不上传账号、文件、报告或扫描内容。分享前检查日志中的本地路径。卸载前取消自启并从托盘退出，备份不会自动删除。

## 开发与验证

Python 3.12 x64 创建 .venv，安装 requirements-build.txt，运行 build.ps1。更新官方基线加 -RefreshBaseline；.release-keys 中的私钥不得分发。构建过滤无关 Poppler ICU，使用 Windows 系统 ICU。两个 EXE 均进行不含 Python PATH 的自测和离屏界面测试，不结束真实 Steam。

```powershell
.\build.ps1
.\dist\SteamSafe-v0.1.1-Beta.exe --self-test --state-dir .\test-output\manual-tests
```

EXE 尚无 Windows Authenticode 签名，可能出现未知发布者提示。验证记录见 QA-report.md。

参考：https://github.com/fenglinbei/IsMySteamSafe 。检查方向重新实现，未嵌入其 C# 程序；不分发 .reference 研究目录。
