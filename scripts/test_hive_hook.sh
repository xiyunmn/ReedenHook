#!/bin/bash
# Hive Hook 测试脚本
# 用途: 验证 Hive 许可证伪造是否生效

set -e

PACKAGE="app.reeden"
TAG_MAIN="ReedenHook"
TAG_HIVE="ReedenHook.HiveForge"
TAG_KWN="ReedenHook.KwnTrigger"

echo "=== ReedenHook v0.2.0 Hive Hook 测试 ==="
echo ""

# 检查设备连接
echo "[1/5] 检查 ADB 连接..."
if ! adb devices | grep -q "device$"; then
    echo "❌ 错误: 没有连接的设备"
    exit 1
fi
echo "✅ 设备已连接"
echo ""

# 检查应用是否安装
echo "[2/5] 检查 Reeden 应用..."
if ! adb shell pm list packages | grep -q "$PACKAGE"; then
    echo "❌ 错误: Reeden 未安装"
    exit 1
fi
echo "✅ Reeden 已安装"
echo ""

# 停止应用
echo "[3/5] 停止 Reeden..."
adb shell am force-stop "$PACKAGE"
sleep 1
echo "✅ 应用已停止"
echo ""

# 清空日志
echo "[4/5] 清空 logcat..."
adb logcat -c
echo "✅ 日志已清空"
echo ""

# 启动应用并监控日志
echo "[5/5] 启动 Reeden 并监控日志..."
echo "----------------------------------------"
adb shell am start -n "$PACKAGE/.MainActivity"
sleep 1

echo ""
echo ">>> 监控 Hive Hook 日志（按 Ctrl+C 停止）"
echo ">>> 预期: 看到 'Intercepted Hive.get(\"loc.jbn\")'"
echo ""

# 监控关键日志，30 秒超时
timeout 30s adb logcat -s "$TAG_MAIN:I" "$TAG_HIVE:I" "$TAG_KWN:I" "ReedenHook.Native:I" || true

echo ""
echo "----------------------------------------"
echo ""
echo "=== 测试完成 ==="
echo ""
echo "请检查上述日志，验证以下内容:"
echo "  1. ✅ 'Hive license forge installed' - Hive Hook 已安装"
echo "  2. ✅ 'Kwn trigger installed' - Kwn 触发器已安装"
echo "  3. ✅ 'Intercepted Hive.get(...)' - 成功拦截许可证读取"
echo "  4. ✅ 'Attempting to trigger Kwn' - Kwn 刷新已触发"
echo "  5. ✅ 'install done ok=99' - 二进制补丁成功"
echo ""
echo "如果缺少任何日志，请参考故障排查指南:"
echo "  local_docs/v0.2.0_implementation_guide.md#故障排查"
