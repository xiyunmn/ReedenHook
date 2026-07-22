package com.xiyunmn.reedenhook.feature.premium

import android.content.Context
import android.util.Base64
import com.xiyunmn.reedenhook.core.HookApi
import com.xiyunmn.reedenhook.host.HostAot
import com.xiyunmn.reedenhook.host.HostPackages
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Publishes the local license cache directly from the target app process.
 *
 * The module runs inside app.reeden, so app-private files are writable without
 * elevated privileges. The writer only appends complete Hive frames and skips
 * when the latest active license already matches the current host version.
 */
object LicenseCachePublisher {
    private const val TAG = "ReedenHook.Cache"
    private const val SETTINGS_HIVE = "databases/settings.hive"

    private const val HIVE_VALUE_INT = 0x01
    private const val HIVE_VALUE_BOOL = 0x03
    private const val HIVE_VALUE_STRING = 0x04
    private const val HIVE_KEY_INT = 0x00
    private const val HIVE_KEY_STRING = 0x01

    private const val SOURCE_KEY_B64 = "EjRWeJq83vAaAhZqEOvvYAA+BGYiIkCSFukK"
    private const val DEFAULT_TOKEN = "reedenhook-local-token"
    private const val ACTIVATED_AT = "2026-07-22T00:00:00.000Z"

    private const val KEY_LICENSE = "license"
    private const val KEY_LICENSE_KEY = "license_key"
    private const val KEY_EMAIL = "license.email"
    private const val KEY_LAST_OK = "license.lastCheckOkTime"
    private const val KEY_FAILED_COUNT = "license.lastCheckFailedCount"
    private const val KEY_ACCESS_TOKEN = "license.accessToken"

    private val deriveSeeds = intArrayOf(31, 122, 66)
    private val secureRandom = SecureRandom()
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "ReedenLicenseCache").apply { isDaemon = true }
    }

    private val crcTable: IntArray by lazy { buildCrc32Table() }
    private val aesKey: ByteArray by lazy { deriveReedenKey() }
    private val keyCrc: Int by lazy {
        hiveCrc32(MessageDigest.getInstance("SHA-256").digest(aesKey))
    }

    fun requestPublish(context: Context, reason: String) {
        val appContext = context.applicationContext ?: context
        executor.execute {
            publishNow(appContext, reason)
        }
    }

    private fun publishNow(context: Context, reason: String) {
        runCatching {
            val file = File(context.filesDir, SETTINGS_HIVE)
            file.parentFile?.mkdirs()
            if (!file.exists() && !file.createNewFile()) {
                error("settings store is unavailable")
            }

            val before = file.readBytes()
            val beforeState = parseState(before)
            if (beforeState.isCurrent()) {
                HookApi.d(
                    "License cache current ($reason): frames=${beforeState.frameCount}",
                    tag = TAG,
                )
                return
            }

            val appendBytes = buildPublishFrames()
            FileOutputStream(file, true).use { stream ->
                stream.write(appendBytes)
                stream.fd.sync()
            }

            val afterState = parseState(file.readBytes())
            if (afterState.isCurrent()) {
                HookApi.i(
                    "License cache published ($reason): " +
                        "frames=${beforeState.frameCount}->${afterState.frameCount}, " +
                        "previous=${beforeState.summary()}",
                    tag = TAG,
                )
            } else {
                HookApi.w(
                    "License cache append did not become latest ($reason): " +
                        "state=${afterState.summary()}",
                    tag = TAG,
                )
            }
        }.onFailure { throwable ->
            HookApi.w(
                "License cache publish skipped ($reason): ${throwable.message ?: throwable.javaClass.name}",
                tag = TAG,
            )
        }
    }

    private fun buildPublishFrames(): ByteArray {
        val licenseKey = desiredLicenseKey()
        val licenseJson =
            "{\"email\":\"${HostAot.FORGE_EMAIL}\"," +
                "\"licenseKey\":\"$licenseKey\"," +
                "\"valid\":true," +
                "\"orderId\":\"${HostAot.FORGE_ORDER_ID}\"," +
                "\"activatedAt\":\"$ACTIVATED_AT\"}"
        val nowSeconds = System.currentTimeMillis() / 1000L
        val frames = listOf(
            buildFrame(KEY_LICENSE, encodeHiveString(licenseJson)),
            buildFrame(KEY_LICENSE_KEY, encodeHiveString(licenseKey)),
            buildFrame(KEY_EMAIL, encodeHiveString(HostAot.FORGE_EMAIL)),
            buildFrame(KEY_LAST_OK, encodeHiveInt(nowSeconds)),
            buildFrame(KEY_FAILED_COUNT, encodeHiveInt(0)),
            buildFrame(KEY_ACCESS_TOKEN, encodeHiveString(DEFAULT_TOKEN)),
        )
        return concat(frames)
    }

    private fun parseState(data: ByteArray): CacheState {
        var offset = 0
        var frameCount = 0
        var latestLicense: String? = null
        var licenseDeleted = false
        var latestLicenseKey: String? = null

        while (offset + 8 <= data.size) {
            val length = readUInt32Le(data, offset).toInt()
            if (length < 8 || offset + length > data.size) {
                error("invalid frame #$frameCount at 0x${offset.toString(16)} length=$length")
            }

            val frameWithoutCrc = data.copyOfRange(offset, offset + length - 4)
            val storedCrc = readUInt32Le(data, offset + length - 4)
            val computedCrc = keyCrc.hiveThen(frameWithoutCrc).toUnsignedLong()
            if (storedCrc != computedCrc) {
                error("CRC mismatch at frame #$frameCount")
            }

            val keyInfo = readHiveKey(frameWithoutCrc)
            val key = keyInfo.key as? String
            val valueStart = offset + keyInfo.valueOffset
            val valueEnd = offset + length - 4
            if (key == KEY_LICENSE || key == KEY_LICENSE_KEY) {
                val deleted = valueStart == valueEnd
                if (key == KEY_LICENSE && deleted) {
                    latestLicense = null
                    licenseDeleted = true
                } else if (key == KEY_LICENSE_KEY && deleted) {
                    latestLicenseKey = null
                } else {
                    val value = decodeHiveValue(decryptValue(data.copyOfRange(valueStart, valueEnd)))
                    if (key == KEY_LICENSE && value is String) {
                        latestLicense = value
                        licenseDeleted = false
                    } else if (key == KEY_LICENSE_KEY && value is String) {
                        latestLicenseKey = value
                    }
                }
            }

            offset += length
            frameCount += 1
        }

        if (offset != data.size) {
            error("trailing bytes after frame parse")
        }

        return CacheState(
            frameCount = frameCount,
            latestLicense = latestLicense,
            licenseDeleted = licenseDeleted,
            latestLicenseKey = latestLicenseKey,
        )
    }

    private fun buildFrame(keyName: String, encodedValue: ByteArray): ByteArray {
        val encryptedValue = encryptValue(encodedValue)
        val body = ByteArrayOutputStream().apply {
            write(encodeHiveKey(keyName))
            write(encryptedValue)
        }.toByteArray()
        val frameLength = 4 + body.size + 4
        val frameWithoutCrc = ByteArrayOutputStream().apply {
            writeUInt32Le(frameLength.toLong())
            write(body)
        }.toByteArray()
        val crc = keyCrc.hiveThen(frameWithoutCrc)
        return ByteArrayOutputStream().apply {
            write(frameWithoutCrc)
            writeUInt32Le(crc.toUnsignedLong())
        }.toByteArray()
    }

    private fun encryptValue(plain: ByteArray): ByteArray {
        val iv = ByteArray(16).also(secureRandom::nextBytes)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(aesKey, "AES"),
            IvParameterSpec(iv),
        )
        return concat(listOf(iv, cipher.doFinal(plain)))
    }

    private fun decryptValue(encrypted: ByteArray): ByteArray {
        if (encrypted.size < 32 || (encrypted.size - 16) % 16 != 0) {
            error("invalid encrypted value length=${encrypted.size}")
        }
        val iv = encrypted.copyOfRange(0, 16)
        val cipherText = encrypted.copyOfRange(16, encrypted.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(aesKey, "AES"),
            IvParameterSpec(iv),
        )
        return cipher.doFinal(cipherText)
    }

    private fun encodeHiveString(value: String): ByteArray {
        val raw = value.toByteArray(Charsets.UTF_8)
        return ByteArrayOutputStream().apply {
            write(HIVE_VALUE_STRING)
            writeUInt32Le(raw.size.toLong())
            write(raw)
        }.toByteArray()
    }

    private fun encodeHiveInt(value: Long): ByteArray {
        return ByteArrayOutputStream().apply {
            write(HIVE_VALUE_INT)
            write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putDouble(value.toDouble()).array())
        }.toByteArray()
    }

    private fun encodeHiveKey(key: String): ByteArray {
        val raw = key.toByteArray(Charsets.UTF_8)
        require(raw.size <= 0xff) { "Hive key is too long" }
        return ByteArrayOutputStream().apply {
            write(HIVE_KEY_STRING)
            write(raw.size)
            write(raw)
        }.toByteArray()
    }

    private fun readHiveKey(frameWithoutCrc: ByteArray): KeyInfo {
        var offset = 4
        if (offset >= frameWithoutCrc.size) {
            error("missing key type")
        }
        return when (val keyType = frameWithoutCrc[offset++].toInt() and 0xff) {
            HIVE_KEY_INT -> {
                val key = readUInt32Le(frameWithoutCrc, offset).toInt()
                KeyInfo(key = key, valueOffset = offset + 4)
            }
            HIVE_KEY_STRING -> {
                if (offset >= frameWithoutCrc.size) {
                    error("missing string key length")
                }
                val length = frameWithoutCrc[offset++].toInt() and 0xff
                if (offset + length > frameWithoutCrc.size) {
                    error("truncated string key")
                }
                val key = String(frameWithoutCrc, offset, length, Charsets.UTF_8)
                KeyInfo(key = key, valueOffset = offset + length)
            }
            else -> error("unsupported key type 0x${keyType.toString(16)}")
        }
    }

    private fun decodeHiveValue(plain: ByteArray): Any {
        if (plain.isEmpty()) {
            error("empty plain value")
        }
        return when (plain[0].toInt() and 0xff) {
            HIVE_VALUE_STRING -> {
                if (plain.size < 5) {
                    error("truncated string value")
                }
                val length = readUInt32Le(plain, 1).toInt()
                if (5 + length > plain.size) {
                    error("truncated string payload")
                }
                String(plain, 5, length, Charsets.UTF_8)
            }
            HIVE_VALUE_INT -> {
                if (plain.size < 9) {
                    error("truncated int value")
                }
                ByteBuffer.wrap(plain, 1, 8).order(ByteOrder.LITTLE_ENDIAN).double.toLong()
            }
            HIVE_VALUE_BOOL -> {
                if (plain.size < 2) {
                    error("truncated bool value")
                }
                plain[1].toInt() != 0
            }
            else -> error("unsupported value type 0x${(plain[0].toInt() and 0xff).toString(16)}")
        }
    }

    private fun deriveReedenKey(): ByteArray {
        val raw = Base64.decode(SOURCE_KEY_B64, Base64.NO_WRAP)
        val out = ByteArray(32)
        var outIndex = 0
        for (index in 8 until raw.size) {
            var acc = raw[index].toInt() and 0xff
            for (seed in deriveSeeds) {
                acc = rotateRight8(acc, 3) xor seed
            }
            acc = (acc - ((outIndex % 7) + 5)) and 0xff
            if (outIndex < out.size) {
                out[outIndex] = acc.toByte()
            }
            outIndex += 1
        }
        return out
    }

    private fun rotateRight8(value: Int, bits: Int): Int {
        val clean = value and 0xff
        return ((clean ushr bits) or (clean shl (8 - bits))) and 0xff
    }

    private fun buildCrc32Table(): IntArray {
        return IntArray(256) { n ->
            var c = n
            repeat(8) {
                c = if ((c and 1) != 0) {
                    0xedb88320.toInt() xor (c ushr 1)
                } else {
                    c ushr 1
                }
            }
            c
        }
    }

    private fun hiveCrc32(data: ByteArray, crc: Int = 0): Int {
        var current = crc xor -0x1
        for (byte in data) {
            current = crcTable[(current xor (byte.toInt() and 0xff)) and 0xff] xor (current ushr 8)
        }
        return current xor -0x1
    }

    private fun Int.hiveThen(data: ByteArray): Int = hiveCrc32(data, this)

    private fun Int.toUnsignedLong(): Long = toLong() and 0xffffffffL

    private fun readUInt32Le(data: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 4 > data.size) {
            error("truncated uint32")
        }
        return (data[offset].toLong() and 0xff) or
            ((data[offset + 1].toLong() and 0xff) shl 8) or
            ((data[offset + 2].toLong() and 0xff) shl 16) or
            ((data[offset + 3].toLong() and 0xff) shl 24)
    }

    private fun ByteArrayOutputStream.writeUInt32Le(value: Long) {
        write((value and 0xff).toInt())
        write(((value ushr 8) and 0xff).toInt())
        write(((value ushr 16) and 0xff).toInt())
        write(((value ushr 24) and 0xff).toInt())
    }

    private fun concat(parts: List<ByteArray>): ByteArray {
        val totalSize = parts.sumOf { it.size }
        return ByteArrayOutputStream(totalSize).apply {
            parts.forEach { write(it) }
        }.toByteArray()
    }

    private fun desiredLicenseKey(): String = "RH-LOCAL-UNLOCK-${HostPackages.VERSION_NAME}"

    private data class KeyInfo(
        val key: Any,
        val valueOffset: Int,
    )

    private data class CacheState(
        val frameCount: Int,
        val latestLicense: String?,
        val licenseDeleted: Boolean,
        val latestLicenseKey: String?,
    ) {
        fun isCurrent(): Boolean {
            val license = latestLicense ?: return false
            return !licenseDeleted &&
                latestLicenseKey == desiredLicenseKey() &&
                license.contains("\"valid\":true") &&
                license.contains("\"licenseKey\":\"${desiredLicenseKey()}\"")
        }

        fun summary(): String {
            return when {
                licenseDeleted -> "license_deleted"
                latestLicense == null -> "license_missing"
                latestLicenseKey != desiredLicenseKey() -> "key=${latestLicenseKey ?: "missing"}"
                else -> "not_current"
            }
        }
    }
}
