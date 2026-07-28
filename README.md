# ReedenHook

ReedenHook 是面向 Reeden 的 LSPosed 模块，用于在本机授权的测试环境中保持会员状态与功能解锁稳定。模块基于现代 libxposed API 102 开发。

当前主要适配：

```text
Reeden 1.37.1 build 694
app.reeden
```

当前模块版本：

```text
ReedenHook 0.5.2
com.xiyunmn.reedenhook
```

## 安装

1. 在支持 libxposed API 102 的 LSPosed 中安装并启用模块。
2. 将作用域只设置为 Reeden（`app.reeden`）。
3. 强制停止并重新启动 Reeden。
4. 打开 Reeden 后确认会员状态和会员功能是否保持可用（有时可能需要第二次冷启动后生效）。
5. 如需排查问题，优先查看模块文件日志。

模块没有独立设置界面；安装、启用作用域并重启宿主后自动生效。

## 主要功能

- 优先通过网络覆写与本地许可证维护保持会员状态。
- 自动写入、检查并修复宿主本地许可证缓存。
- 只阻断许可证校验相关域名，不影响宿主其它网络请求。
- 当主路径无法保持本地许可证存在时，才启用 AOT gate 兜底。
- 提供宿主私有目录文件日志，并限制单文件大小和轮转数量。

## 当前策略

模块入口保持单一路径：

```text
Network override + local license forge -> primary path
AOT gate -> fallback only
```

正常运行时，主路径应进入稳定状态，AOT 兜底不应被触发。若日志中出现 `FALLBACK_ARMED` 或 `AOT_GATE_INSTALLED`，说明本地许可证主路径已经被判定失效，需要优先检查许可证文件和网络 guard。

## 使用建议

- 首次安装或升级模块后，先强制停止 Reeden，再重新打开。
- 宿主版本更新后，请先确认基础启动、会员状态和核心会员功能是否正常。
- 不建议同时启用其它会修改 Reeden 会员、许可证或网络校验逻辑的模块。
- 如果会员状态启动后很快回退，优先查看文件日志中的 `local license`、`network guard` 和 `getaddrinfo` 记录。

## 日志

logcat 标签：

```text
ReedenHook
ReedenHook.Module
ReedenHook.Network
ReedenHook.Native
```

文件日志：

```text
/data/user/0/app.reeden/files/reedenhook/logs/reedenhook.log
```

文件日志只写入宿主私有目录，按 256KB 单文件、最多 3 个文件轮转。

常用查看命令：

```powershell
adb logcat -d -s ReedenHook ReedenHook.Module ReedenHook.Network ReedenHook.Native
```

正常日志通常会包含：

```text
NetworkLicenseOverrideFeature.install
network guard hooked libflutter.so!getaddrinfo
license getaddrinfo blocked
local license cache intact
PRIMARY_STABLE
```

正常主路径下通常不应出现：

```text
FALLBACK_ARMED
AOT_GATE_INSTALLED
FATAL EXCEPTION
UnsatisfiedLinkError
```

## 兼容性

当前真机验证版本为 Reeden 1.37.1 build 694。Reeden 1.36.1 build 684 是逆向分析基线。

跨版本兼容主要依赖以下内容是否保持稳定：

- 许可证域名仍为 `license.reeden.app` 或 `license-cn.reeden.app`。
- 本地许可证仍存储在 `settings.hive`。
- 许可证相关键名和 Hive 加密格式没有变化。
- Flutter / Dart AOT 的兜底门禁结构仍能被唯一识别。

小版本更新通常优先验证主路径；只有主路径失效时才需要重新分析 AOT 兜底。

## 构建

构建需要 JDK 17、Android SDK 和 NDK。推荐使用 PowerShell 7：

```powershell
cd E:\AndroidStudioProjects\ReedenHook
.\gradlew.bat :app:assembleDebug
```

安装调试包：

```powershell
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

项目会在 `:app:preBuild` 前执行架构检查，确认 libxposed API 102 元数据、作用域和入口配置没有偏离。


## 免责声明

使用 LSPosed 模块可能导致宿主异常、功能失效、数据损坏或其它不可预期后果，请在使用前做好备份，并自行承担使用风险。
