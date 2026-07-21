#!/bin/bash
# Hive 加密密钥提取脚本
# 需要: root 权限

set -e

PACKAGE="app.reeden"
HIVE_DIR="/data/data/$PACKAGE/files"
OUTPUT_DIR="./artifacts/host/hive_extracted"

echo "=== Hive 加密密钥提取 ==="
echo ""
echo "⚠️  警告: 此脚本需要 root 权限"
echo ""

# 检查 root
echo "[1/6] 检查 root 权限..."
if ! adb shell "su -c 'id'" | grep -q "uid=0"; then
    echo "❌ 错误: 设备未 root 或 su 不可用"
    exit 1
fi
echo "✅ Root 权限可用"
echo ""

# 创建输出目录
echo "[2/6] 创建输出目录..."
mkdir -p "$OUTPUT_DIR"
echo "✅ 目录创建: $OUTPUT_DIR"
echo ""

# 列出 Hive 文件
echo "[3/6] 列出 Hive 文件..."
adb shell "su -c 'ls -lh $HIVE_DIR/databases/'"
echo ""

# 提取 settings.hive
echo "[4/6] 提取 settings.hive..."
adb shell "su -c 'cp $HIVE_DIR/databases/settings.hive /sdcard/'"
adb pull /sdcard/settings.hive "$OUTPUT_DIR/"
adb shell "rm /sdcard/settings.hive"
echo "✅ 已保存: $OUTPUT_DIR/settings.hive"
echo ""

# 提取 .lock 文件（加密密钥）
echo "[5/6] 提取加密密钥..."
if adb shell "su -c 'test -f $HIVE_DIR/.hive.db/.lock'"; then
    adb shell "su -c 'cp $HIVE_DIR/.hive.db/.lock /sdcard/'"
    adb pull /sdcard/.lock "$OUTPUT_DIR/hive_key.lock"
    adb shell "rm /sdcard/.lock"
    echo "✅ 已保存: $OUTPUT_DIR/hive_key.lock"
else
    echo "⚠️  警告: 未找到 .lock 文件，可能使用其他密钥存储方式"
fi
echo ""

# 提取 FlutterSecureStorage（如果存在）
echo "[6/6] 检查 FlutterSecureStorage..."
if adb shell "su -c 'test -d $HIVE_DIR/flutter_secure_storage'"; then
    adb shell "su -c 'cp -r $HIVE_DIR/flutter_secure_storage /sdcard/'"
    adb pull /sdcard/flutter_secure_storage "$OUTPUT_DIR/"
    adb shell "rm -rf /sdcard/flutter_secure_storage"
    echo "✅ 已保存: $OUTPUT_DIR/flutter_secure_storage/"
else
    echo "ℹ️  FlutterSecureStorage 不存在"
fi
echo ""

echo "=== 提取完成 ==="
echo ""
echo "文件位置:"
echo "  - settings.hive: $OUTPUT_DIR/settings.hive"
echo "  - 加密密钥: $OUTPUT_DIR/hive_key.lock (如果存在)"
echo ""
echo "下一步:"
echo "  1. 使用 Python 脚本解密 Hive 文件"
echo "  2. 查找 'loc.jbn' 键的实际值"
echo "  3. 验证 GZc JSON 格式"
echo ""
echo "参考: local_docs/hive_license_forge_analysis.md"
