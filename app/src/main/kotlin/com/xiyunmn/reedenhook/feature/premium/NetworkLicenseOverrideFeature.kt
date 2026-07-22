package com.xiyunmn.reedenhook.feature.premium

import android.app.Application
import android.content.Context
import android.os.FileObserver
import com.xiyunmn.reedenhook.core.HookApi
import com.xiyunmn.reedenhook.host.HostAot
import com.xiyunmn.reedenhook.host.HostPackages
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.net.URLConnection
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.lang.reflect.Modifier
import java.util.Collections
import java.util.Locale
import java.util.WeakHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Network-first license override.
 *
 * This deliberately avoids Dart AOT/native patching. It only rewrites Java URL
 * stack responses for Reeden's license hosts, and logs every matched URL so we
 * can distinguish a Java-network hit from a Dart-native network path.
 */
object NetworkLicenseOverrideFeature {
    private const val TAG = "ReedenHook.Network"
    private const val TOKEN = "reedenhook-local-token"
    private const val DEVICE_ID_FALLBACK = "reedenhook-device"
    private const val ACTIVATED_AT = "2026-07-22T00:00:00.000Z"
    private const val HIVE_SETTINGS_RELATIVE_PATH = "databases/settings.hive"
    private const val HIVE_SETTINGS_FILE_NAME = "settings.hive"
    private const val HIVE_STRING_TYPE = 0x04
    private const val HIVE_INT_TYPE = 0x01
    private const val HIVE_KEY_STRING_TYPE = 0x01
    private const val LOCAL_REPAIR_MIN_INTERVAL_MS = 200L
    private const val LOCAL_POLL_INTERVAL_MS = 2_500L
    private const val LOCAL_WATCH_MASK =
        FileObserver.CLOSE_WRITE or
            FileObserver.CREATE or
            FileObserver.DELETE or
            FileObserver.MOVED_TO or
            FileObserver.MODIFY or
            FileObserver.DELETE_SELF or
            FileObserver.MOVE_SELF
    private val HIVE_KEY = hex("776a733c707a7b3c6b676b3956554c32737d6b00000000000000000000000000")
    private val CRC32_TABLE = buildCrc32Table()
    private val HIVE_KEY_CRC = hiveCrc32(MessageDigest.getInstance("SHA-256").digest(HIVE_KEY), 0)
    private val installed = AtomicBoolean(false)
    private val urlHits = AtomicInteger(0)
    private val responseHits = AtomicInteger(0)
    private val localRepairLock = Any()
    private val localGuardianStarted = AtomicBoolean(false)
    private val localRepairChecks = AtomicInteger(0)
    private val localRepairWrites = AtomicInteger(0)
    private val localRepairSkips = AtomicInteger(0)
    private val networkGuardStarted = AtomicBoolean(false)
    private var localLastRepairAt = 0L
    private var localBackupDone = false
    private var localObserver: FileObserver? = null
    private val targetConnections = Collections.synchronizedMap(WeakHashMap<Any, String>())
    private val requestBodies = Collections.synchronizedMap(WeakHashMap<Any, ByteArrayOutputStream>())
    private val targetHosts = setOf(
        "license.reeden.app",
        "license-cn.reeden.app",
    )

    fun install(module: XposedModule, classLoader: ClassLoader, processName: String) {
        if (!installed.compareAndSet(false, true)) {
            HookApi.w("NetworkLicenseOverrideFeature already installed", TAG)
            return
        }
        HookApi.i(
            "NetworkLicenseOverrideFeature.install process=${HostPackages.processLabel(processName)}, " +
                "mode=network_response_override hosts=${targetHosts.joinToString(",")}",
            TAG,
        )
        startNativeNetworkGuard("feature.install")
        installLocalLicenseRepairHooks(module)
        installUrlHooks(module)
        installConnectionHooks(module, classLoader)
    }

    fun installAfterHotReload(
        module: XposedModule,
        classLoader: ClassLoader,
        processName: String,
        oldHandles: Collection<XposedInterface.HookHandle>,
    ) {
        HookApi.i(
            "NetworkLicenseOverrideFeature.installAfterHotReload process=${HostPackages.processLabel(processName)}, " +
                "oldHandles=${oldHandles.size}",
            TAG,
        )
        installed.set(false)
        install(module, classLoader, processName)
    }

    fun onHotReloading() {
        HookApi.i(
            "NetworkLicenseOverrideFeature.onHotReloading cleanup " +
                "urlHits=${urlHits.get()} responseHits=${responseHits.get()} " +
                "localChecks=${localRepairChecks.get()} localWrites=${localRepairWrites.get()}",
            TAG,
        )
        installed.set(false)
        targetConnections.clear()
        requestBodies.clear()
        runCatching { localObserver?.stopWatching() }
        localObserver = null
        localGuardianStarted.set(false)
        networkGuardStarted.set(false)
        NativeNetworkGuard.setEnabled(false)
        synchronized(localRepairLock) {
            localLastRepairAt = 0L
            localBackupDone = false
        }
    }

    private fun installLocalLicenseRepairHooks(module: XposedModule) {
        HookApi.interceptProtective(
            module = module,
            executable = HookApi.findDeclaredMethodOrNull(
                Application::class.java,
                "attach",
                Context::class.java,
            ),
            feature = "Network.Application.attach.localLicenseRepair",
            id = "network.Application.attach.localLicenseRepair",
        ) { chain ->
            startLocalLicenseGuardian(chain.getArg(0) as? Context, "Application.attach.before")
            chain.proceed()
        }

        HookApi.interceptProtective(
            module = module,
            executable = HookApi.findDeclaredMethodOrNull(Application::class.java, "onCreate"),
            feature = "Network.Application.onCreate.localLicenseRepair",
            id = "network.Application.onCreate.localLicenseRepair",
        ) { chain ->
            val result = chain.proceed()
            startLocalLicenseGuardian(chain.getThisObject() as? Context, "Application.onCreate.after")
            result
        }
    }

    private fun startLocalLicenseGuardian(context: Context?, reason: String) {
        val appContext = context?.applicationContext ?: context
        if (appContext == null || appContext.packageName != HostPackages.TARGET) {
            return
        }

        val logPaths = HookApi.configureHostFileLogging(appContext, reason)
        NativeNetworkGuard.configureFileLogging(logPaths)
        startNativeNetworkGuard(reason)
        repairLocalLicense(appContext, "$reason.immediate")
        if (!localGuardianStarted.compareAndSet(false, true)) {
            return
        }

        installHiveObserver(appContext)
        Thread(
            {
                val earlyDelays = longArrayOf(250L, 500L, 1_000L, 2_000L, 4_000L, 8_000L, 15_000L)
                earlyDelays.forEachIndexed { index, delayMs ->
                    runCatching { Thread.sleep(delayMs) }
                    if (!NativeNetworkGuard.isInstalled()) {
                        startNativeNetworkGuard("guardian.early.$index.${delayMs}ms")
                    }
                    repairLocalLicense(appContext, "guardian.early.$index.${delayMs}ms")
                }
                while (localGuardianStarted.get()) {
                    runCatching { Thread.sleep(LOCAL_POLL_INTERVAL_MS) }
                    if (!NativeNetworkGuard.isInstalled()) {
                        startNativeNetworkGuard("guardian.poll")
                    }
                    repairLocalLicense(appContext, "guardian.poll")
                }
            },
            "ReedenHook-LicenseGuardian",
        ).apply {
            isDaemon = true
            start()
        }
        HookApi.i("local license cache guard started path=${hiveFileFor(appContext).absolutePath}", TAG)
    }

    private fun startNativeNetworkGuard(reason: String) {
        if (NativeNetworkGuard.isInstalled()) {
            return
        }
        if (!networkGuardStarted.compareAndSet(false, true)) {
            val code = NativeNetworkGuard.install("$reason.retry")
            if (code != -1 && code != -3) {
                networkGuardStarted.set(NativeNetworkGuard.isInstalled())
            }
            return
        }
        Thread(
            {
                val attempts = longArrayOf(0L, 120L, 300L, 700L, 1_500L, 3_000L, 6_000L, 10_000L)
                attempts.forEachIndexed { index, delayMs ->
                    if (delayMs > 0) {
                        runCatching { Thread.sleep(delayMs) }
                    }
                    val code = NativeNetworkGuard.install("$reason.native.$index")
                    if (code == 0 || NativeNetworkGuard.isInstalled()) {
                        return@Thread
                    }
                }
                networkGuardStarted.set(false)
                HookApi.w("NativeNetworkGuard not installed after retries status=${NativeNetworkGuard.status()}", TAG)
            },
            "ReedenHook-NetworkGuard",
        ).apply {
            isDaemon = true
            start()
        }
    }

    private fun installHiveObserver(context: Context) {
        val hiveFile = hiveFileFor(context)
        val parent = hiveFile.parentFile ?: return
        if (!parent.exists() && !parent.mkdirs()) {
            HookApi.w("local license observer skipped: cannot create ${parent.absolutePath}", TAG)
            return
        }
        val observer = object : FileObserver(parent.absolutePath, LOCAL_WATCH_MASK) {
            override fun onEvent(event: Int, path: String?) {
                if (path != null && path != HIVE_SETTINGS_FILE_NAME) {
                    return
                }
                if ((event and LOCAL_WATCH_MASK) == 0) {
                    return
                }
                repairLocalLicense(context, "FileObserver.event=0x${event.toString(16)}")
            }
        }
        localObserver = observer
        runCatching { observer.startWatching() }
            .onSuccess { HookApi.i("local license observer started dir=${parent.absolutePath}", TAG) }
            .onFailure { HookApi.w("local license observer failed: ${it.message}", TAG) }
    }

    private fun repairLocalLicense(context: Context?, reason: String) {
        if (context == null || context.packageName != HostPackages.TARGET) {
            return
        }
        synchronized(localRepairLock) {
            localRepairChecks.incrementAndGet()
            val nowMs = System.currentTimeMillis()
            if (nowMs - localLastRepairAt < LOCAL_REPAIR_MIN_INTERVAL_MS) {
                return
            }
            runCatching {
                val hiveFile = hiveFileFor(context)
                val parent = hiveFile.parentFile
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    error("cannot create ${parent.absolutePath}")
                }

                val data = if (hiveFile.exists()) hiveFile.readBytes() else ByteArray(0)
                val inspection = inspectHive(data)
                if (inspection.completeForgedState && inspection.validPrefixLength == data.size) {
                    val skipped = localRepairSkips.incrementAndGet()
                    if (skipped == 1 || skipped % 20 == 0) {
                        HookApi.i(
                            "local license cache intact reason=$reason frames=${inspection.frameCount} " +
                                "checks=${localRepairChecks.get()} writes=${localRepairWrites.get()} " +
                                "path=${hiveFile.absolutePath}",
                            TAG,
                        )
                    }
                    return
                }

                if (hiveFile.exists() && !localBackupDone) {
                    val backup = File(
                        hiveFile.parentFile,
                        "settings.hive.reedenhook.bak.${System.currentTimeMillis()}",
                    )
                    runCatching { hiveFile.copyTo(backup, overwrite = false) }
                        .onFailure { HookApi.w("local license backup failed: ${it.message}", TAG) }
                    localBackupDone = true
                }

                val base = data.copyOf(inspection.validPrefixLength)
                val repaired = base + buildLocalLicenseFrames()
                if (inspection.validPrefixLength == data.size && hiveFile.exists()) {
                    FileOutputStream(hiveFile, true).use { out ->
                        out.write(repaired, data.size, repaired.size - data.size)
                        out.fd.sync()
                    }
                } else {
                    val tempFile = File(hiveFile.parentFile, "settings.hive.reedenhook.tmp")
                    tempFile.writeBytes(repaired)
                    if (hiveFile.exists() && !hiveFile.delete()) {
                        error("cannot replace ${hiveFile.absolutePath}")
                    }
                    if (!tempFile.renameTo(hiveFile)) {
                        error("cannot rename ${tempFile.absolutePath}")
                    }
                }
                val writes = localRepairWrites.incrementAndGet()
                localLastRepairAt = nowMs
                HookApi.i(
                    "local license repaired #$writes reason=$reason cause=${inspection.repairCause} " +
                        "frames=${inspection.frameCount} " +
                        "trimmed=${data.size - inspection.validPrefixLength} addedBytes=${repaired.size - base.size} " +
                        "path=${hiveFile.absolutePath}",
                    TAG,
                )
            }.onFailure { throwable ->
                HookApi.e("local license repair failed reason=$reason", TAG, throwable)
            }
        }
    }

    private fun hiveFileFor(context: Context): File {
        return File(context.filesDir, HIVE_SETTINGS_RELATIVE_PATH)
    }

    private fun installUrlHooks(module: XposedModule) {
        HookApi.interceptProtective(
            module = module,
            executable = HookApi.findDeclaredMethodOrNull(URL::class.java, "openConnection"),
            feature = "Network.URL.openConnection",
            id = "network.URL.openConnection",
        ) { chain ->
            val result = chain.proceed()
            markConnection(chain.getThisObject() as? URL, result)
            result
        }

        HookApi.interceptProtective(
            module = module,
            executable = HookApi.findDeclaredMethodOrNull(URL::class.java, "openConnection", Proxy::class.java),
            feature = "Network.URL.openConnection.Proxy",
            id = "network.URL.openConnection.Proxy",
        ) { chain ->
            val result = chain.proceed()
            markConnection(chain.getThisObject() as? URL, result)
            result
        }

        HookApi.interceptProtective(
            module = module,
            executable = HookApi.findDeclaredMethodOrNull(URL::class.java, "openStream"),
            feature = "Network.URL.openStream",
            id = "network.URL.openStream",
        ) { chain ->
            val url = chain.getThisObject() as? URL
            if (isTargetUrl(url)) {
                val urlText = url.toString()
                HookApi.i("URL.openStream override hit url=$urlText", TAG)
                responseHits.incrementAndGet()
                ByteArrayInputStream(payloadFor(urlText = urlText, body = null))
            } else {
                chain.proceed()
            }
        }
    }

    private fun installConnectionHooks(module: XposedModule, classLoader: ClassLoader) {
        val classNames = listOf(
            "java.net.URLConnection",
            "java.net.HttpURLConnection",
            "javax.net.ssl.HttpsURLConnection",
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
            "com.android.okhttp.internal.huc.HttpsURLConnectionImpl",
            "com.android.okhttp.internal.huc.DelegatingHttpsURLConnection",
        )
        classNames.mapNotNull { findClassOrNull(it, classLoader) }
            .distinct()
            .forEach { clazz ->
                hookNoArg(module, clazz, "connect", "connect") { _, _, urlText ->
                    HookApi.i("connect suppressed url=$urlText", TAG)
                    null
                }
                hookNoArg(module, clazz, "getOutputStream", "getOutputStream") { _, connection, urlText ->
                    HookApi.i("request body recorder attached url=$urlText", TAG)
                    RecordingOutputStream(connection)
                }
                hookNoArg(module, clazz, "getInputStream", "getInputStream") { _, connection, urlText ->
                    responseStream(connection, urlText)
                }
                hookNoArg(module, clazz, "getErrorStream", "getErrorStream") { _, connection, urlText ->
                    responseStream(connection, urlText)
                }
                hookNoArg(module, clazz, "getResponseCode", "getResponseCode") { _, _, urlText ->
                    HookApi.i("responseCode override url=$urlText", TAG)
                    HttpURLConnection.HTTP_OK
                }
                hookNoArg(module, clazz, "getResponseMessage", "getResponseMessage") { _, _, _ ->
                    "OK"
                }
                hookNoArg(module, clazz, "getContentType", "getContentType") { _, _, _ ->
                    "application/json; charset=utf-8"
                }
                hookNoArg(module, clazz, "getContentEncoding", "getContentEncoding") { _, _, _ ->
                    null
                }
                hookNoArg(module, clazz, "getContentLength", "getContentLength") { _, connection, urlText ->
                    payloadFor(connection, urlText).size
                }
                hookNoArg(module, clazz, "getContentLengthLong", "getContentLengthLong") { _, connection, urlText ->
                    payloadFor(connection, urlText).size.toLong()
                }
                hookOneArg(
                    module = module,
                    clazz = clazz,
                    methodName = "getHeaderField",
                    parameterType = String::class.java,
                    idSuffix = "getHeaderField.String",
                ) { chain, connection, urlText ->
                    val key = chain.getArg(0) as? String
                    headerValue(key, payloadFor(connection, urlText).size)
                }
                hookOneArg(
                    module = module,
                    clazz = clazz,
                    methodName = "getHeaderField",
                    parameterType = Int::class.javaPrimitiveType ?: Int::class.java,
                    idSuffix = "getHeaderField.Int",
                ) { chain, connection, urlText ->
                    val index = chain.getArg(0) as? Int ?: return@hookOneArg null
                    indexedHeaderValue(index, payloadFor(connection, urlText).size)
                }
                hookOneArg(
                    module = module,
                    clazz = clazz,
                    methodName = "getHeaderFieldKey",
                    parameterType = Int::class.javaPrimitiveType ?: Int::class.java,
                    idSuffix = "getHeaderFieldKey",
                ) { chain, _, _ ->
                    val index = chain.getArg(0) as? Int ?: return@hookOneArg null
                    indexedHeaderKey(index)
                }
                hookNoArg(module, clazz, "getHeaderFields", "getHeaderFields") { _, connection, urlText ->
                    headerFields(payloadFor(connection, urlText).size)
                }
            }
    }

    private fun hookNoArg(
        module: XposedModule,
        clazz: Class<*>,
        methodName: String,
        idSuffix: String,
        replacement: (XposedInterface.Chain, Any, String) -> Any?,
    ) {
        val method = HookApi.findDeclaredMethodOrNull(clazz, methodName) ?: return
        if (Modifier.isAbstract(method.modifiers)) {
            HookApi.d("Skip abstract hook target: Network.${clazz.name}.$methodName")
            return
        }
        HookApi.interceptProtective(
            module = module,
            executable = method,
            feature = "Network.${clazz.name}.$methodName",
            id = "network.${clazz.name}.$idSuffix",
        ) { chain ->
            val connection = chain.getThisObject() ?: return@interceptProtective chain.proceed()
            val urlText = targetUrlForConnection(connection)
            if (urlText == null) {
                chain.proceed()
            } else {
                replacement(chain, connection, urlText)
            }
        }
    }

    private fun hookOneArg(
        module: XposedModule,
        clazz: Class<*>,
        methodName: String,
        parameterType: Class<*>,
        idSuffix: String,
        replacement: (XposedInterface.Chain, Any, String) -> Any?,
    ) {
        val method = HookApi.findDeclaredMethodOrNull(clazz, methodName, parameterType) ?: return
        if (Modifier.isAbstract(method.modifiers)) {
            HookApi.d("Skip abstract hook target: Network.${clazz.name}.$methodName")
            return
        }
        HookApi.interceptProtective(
            module = module,
            executable = method,
            feature = "Network.${clazz.name}.$methodName",
            id = "network.${clazz.name}.$idSuffix",
        ) { chain ->
            val connection = chain.getThisObject() ?: return@interceptProtective chain.proceed()
            val urlText = targetUrlForConnection(connection)
            if (urlText == null) {
                chain.proceed()
            } else {
                replacement(chain, connection, urlText)
            }
        }
    }

    private fun markConnection(url: URL?, result: Any?) {
        if (!isTargetUrl(url) || result !is URLConnection) {
            return
        }
        val urlText = url.toString()
        targetConnections[result] = urlText
        val count = urlHits.incrementAndGet()
        HookApi.i("license URLConnection marked #$count class=${result.javaClass.name} url=$urlText", TAG)
    }

    private fun responseStream(connection: Any, urlText: String): ByteArrayInputStream {
        val payload = payloadFor(connection, urlText)
        val count = responseHits.incrementAndGet()
        HookApi.i("response body override #$count bytes=${payload.size} url=$urlText", TAG)
        return ByteArrayInputStream(payload)
    }

    private fun payloadFor(connection: Any, urlText: String): ByteArray {
        val body = requestBodies[connection]?.toByteArray()?.toString(StandardCharsets.UTF_8)
        return payloadFor(urlText = urlText, body = body)
    }

    private fun payloadFor(urlText: String, body: String?): ByteArray {
        val request = RequestFields.from(body.orEmpty())
        val licenseKey = request.licenseKey.ifBlank { HostAot.FORGE_LICENSE_KEY }
        val deviceId = request.deviceId.ifBlank { DEVICE_ID_FALLBACK }
        val orderId = request.orderId.ifBlank { HostAot.FORGE_ORDER_ID }
        val email = request.email.ifBlank { HostAot.FORGE_EMAIL }
        val licenseObject =
            """{"email":"${json(email)}","licenseKey":"${json(licenseKey)}","license_key":"${json(licenseKey)}","valid":true,"orderId":"${json(orderId)}","order_id":"${json(orderId)}","activatedAt":"$ACTIVATED_AT","activated_at":"$ACTIVATED_AT"}"""
        val activationInfo =
            """{"email":"${json(email)}","licenseKey":"${json(licenseKey)}","license_key":"${json(licenseKey)}","deviceId":"${json(deviceId)}","device_id":"${json(deviceId)}","valid":true,"orderId":"${json(orderId)}","order_id":"${json(orderId)}","activatedAt":"$ACTIVATED_AT","activated_at":"$ACTIVATED_AT","accessToken":"$TOKEN","access_token":"$TOKEN"}"""
        val payload =
            """{"success":true,"code":0,"message":"success","accessToken":"$TOKEN","token":"$TOKEN","url":"${json(urlText)}","activationInfo":$activationInfo,"license":$licenseObject,"data":{"success":true,"code":0,"message":"success","accessToken":"$TOKEN","token":"$TOKEN","activationInfo":$activationInfo,"license":$licenseObject}}"""
        return payload.toByteArray(StandardCharsets.UTF_8)
    }

    private fun buildLocalLicenseFrames(): ByteArray {
        val nowSeconds = System.currentTimeMillis() / 1000L
        val licenseJson =
            """{"email":"${json(HostAot.FORGE_EMAIL)}","licenseKey":"${json(HostAot.FORGE_LICENSE_KEY)}","valid":true,"orderId":"${json(HostAot.FORGE_ORDER_ID)}","activatedAt":"$ACTIVATED_AT"}"""
        val frames = listOf(
            buildHiveFrame("license", encodeHiveString(licenseJson)),
            buildHiveFrame("license_key", encodeHiveString(HostAot.FORGE_LICENSE_KEY)),
            buildHiveFrame("license.email", encodeHiveString(HostAot.FORGE_EMAIL)),
            buildHiveFrame("license.lastCheckOkTime", encodeHiveInt(nowSeconds)),
            buildHiveFrame("license.lastCheckFailedCount", encodeHiveInt(0L)),
            buildHiveFrame("license.accessToken", encodeHiveString(TOKEN)),
        )
        return frames.fold(ByteArray(0)) { acc, frame -> acc + frame }
    }

    private fun inspectHive(data: ByteArray): HiveInspection {
        var offset = 0
        var frameCount = 0
        var latestLicenseLooksValid = false
        var latestLicenseDeleted = false
        var latestLicenseKeyLooksValid = false
        var latestEmailLooksValid = false
        var latestOkTimeLooksValid = false
        var latestFailedCountLooksValid = false
        var latestAccessTokenLooksValid = false
        while (offset + 8 <= data.size) {
            val length = readLeInt(data, offset)
            if (length < 8 || offset + length > data.size) {
                break
            }
            val frameWithoutCrc = data.copyOfRange(offset, offset + length - 4)
            val storedCrc = readLeInt(data, offset + length - 4)
            val computedCrc = hiveCrc32(frameWithoutCrc, HIVE_KEY_CRC)
            if (storedCrc != computedCrc) {
                break
            }
            val keyInfo = readHiveKeyInfo(data, offset, length) ?: break
            val valueEnd = offset + length - 4
            val deleted = keyInfo.valueOffset == valueEnd
            when (keyInfo.key) {
                "license" -> {
                    latestLicenseDeleted = deleted
                    latestLicenseLooksValid = false
                    if (!deleted) {
                        runCatching {
                            val value = decodeHiveStringValue(
                                decryptHiveValue(data.copyOfRange(keyInfo.valueOffset, valueEnd)),
                            )
                            latestLicenseLooksValid =
                                value.contains(""""valid":true""") &&
                                value.contains(""""licenseKey":"${HostAot.FORGE_LICENSE_KEY}"""")
                        }.onFailure {
                            latestLicenseLooksValid = false
                        }
                    }
                }
                "license_key" -> {
                    latestLicenseKeyLooksValid = !deleted && readEncryptedStringOrNull(
                        data,
                        keyInfo.valueOffset,
                        valueEnd,
                    ) == HostAot.FORGE_LICENSE_KEY
                }
                "license.email" -> {
                    latestEmailLooksValid = !deleted && readEncryptedStringOrNull(
                        data,
                        keyInfo.valueOffset,
                        valueEnd,
                    ) == HostAot.FORGE_EMAIL
                }
                "license.lastCheckFailedCount" -> {
                    latestFailedCountLooksValid = !deleted && readEncryptedIntOrNull(
                        data,
                        keyInfo.valueOffset,
                        valueEnd,
                    ) == 0L
                }
                "license.lastCheckOkTime" -> {
                    latestOkTimeLooksValid = !deleted && readEncryptedIntOrNull(
                        data,
                        keyInfo.valueOffset,
                        valueEnd,
                    ) != null
                }
                "license.accessToken" -> {
                    latestAccessTokenLooksValid = !deleted && readEncryptedStringOrNull(
                        data,
                        keyInfo.valueOffset,
                        valueEnd,
                    ) == TOKEN
                }
            }
            offset += length
            frameCount += 1
        }
        return HiveInspection(
            validPrefixLength = offset,
            frameCount = frameCount,
            latestLicenseLooksValid = latestLicenseLooksValid,
            latestLicenseDeleted = latestLicenseDeleted,
            latestLicenseKeyLooksValid = latestLicenseKeyLooksValid,
            latestEmailLooksValid = latestEmailLooksValid,
            latestOkTimeLooksValid = latestOkTimeLooksValid,
            latestFailedCountLooksValid = latestFailedCountLooksValid,
            latestAccessTokenLooksValid = latestAccessTokenLooksValid,
        )
    }

    private fun readEncryptedStringOrNull(data: ByteArray, valueOffset: Int, valueEnd: Int): String? {
        if (valueOffset >= valueEnd) {
            return null
        }
        return runCatching {
            decodeHiveStringValue(decryptHiveValue(data.copyOfRange(valueOffset, valueEnd)))
        }.getOrNull()
    }

    private fun readEncryptedIntOrNull(data: ByteArray, valueOffset: Int, valueEnd: Int): Long? {
        if (valueOffset >= valueEnd) {
            return null
        }
        return runCatching {
            decodeHiveIntValue(decryptHiveValue(data.copyOfRange(valueOffset, valueEnd)))
        }.getOrNull()
    }

    private fun buildHiveFrame(keyName: String, typedPlaintext: ByteArray): ByteArray {
        val encryptedValue = encryptHiveValue(typedPlaintext)
        val body = encodeHiveKey(keyName) + encryptedValue
        val frameLength = 4 + body.size + 4
        val frameWithoutCrc = writeLeInt(frameLength) + body
        val crc = hiveCrc32(frameWithoutCrc, HIVE_KEY_CRC)
        return frameWithoutCrc + writeLeInt(crc)
    }

    private fun encryptHiveValue(typedPlaintext: ByteArray): ByteArray {
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(HIVE_KEY, "AES"), IvParameterSpec(iv))
        return iv + cipher.doFinal(typedPlaintext)
    }

    private fun decryptHiveValue(encryptedValue: ByteArray): ByteArray {
        require(encryptedValue.size >= 32)
        val iv = encryptedValue.copyOfRange(0, 16)
        val encrypted = encryptedValue.copyOfRange(16, encryptedValue.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(HIVE_KEY, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(encrypted)
    }

    private fun targetUrlForConnection(connection: Any): String? {
        targetConnections[connection]?.let { return it }
        val url = (connection as? URLConnection)?.url
        if (!isTargetUrl(url)) {
            return null
        }
        val urlText = url.toString()
        targetConnections[connection] = urlText
        return urlText
    }

    private fun isTargetUrl(url: URL?): Boolean {
        val host = url?.host?.lowercase(Locale.US) ?: return false
        return host in targetHosts
    }

    private fun findClassOrNull(name: String, classLoader: ClassLoader): Class<*>? {
        return runCatching { Class.forName(name, false, classLoader) }
            .recoverCatching { Class.forName(name, false, ClassLoader.getSystemClassLoader()) }
            .recoverCatching { Class.forName(name) }
            .getOrNull()
    }

    private fun headerValue(name: String?, contentLength: Int): String? {
        return when (name?.lowercase(Locale.US)) {
            null -> "HTTP/1.1 200 OK"
            "content-type" -> "application/json; charset=utf-8"
            "content-length" -> contentLength.toString()
            "cache-control" -> "no-store"
            else -> null
        }
    }

    private fun indexedHeaderKey(index: Int): String? {
        return when (index) {
            0 -> null
            1 -> "Content-Type"
            2 -> "Content-Length"
            3 -> "Cache-Control"
            else -> null
        }
    }

    private fun indexedHeaderValue(index: Int, contentLength: Int): String? {
        return when (index) {
            0 -> "HTTP/1.1 200 OK"
            1 -> "application/json; charset=utf-8"
            2 -> contentLength.toString()
            3 -> "no-store"
            else -> null
        }
    }

    private fun headerFields(contentLength: Int): Map<String, List<String>> {
        return linkedMapOf(
            "Content-Type" to listOf("application/json; charset=utf-8"),
            "Content-Length" to listOf(contentLength.toString()),
            "Cache-Control" to listOf("no-store"),
        )
    }

    private fun json(value: String): String {
        return buildString(value.length + 8) {
            value.forEach { char ->
                when (char) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\b' -> append("\\b")
                    '\u000C' -> append("\\f")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(char)
                }
            }
        }
    }

    private fun encodeHiveKey(value: String): ByteArray {
        val raw = value.toByteArray(StandardCharsets.UTF_8)
        require(raw.size <= 0xFF)
        return byteArrayOf(HIVE_KEY_STRING_TYPE.toByte(), raw.size.toByte()) + raw
    }

    private fun encodeHiveString(value: String): ByteArray {
        val raw = value.toByteArray(StandardCharsets.UTF_8)
        return byteArrayOf(HIVE_STRING_TYPE.toByte()) + writeLeInt(raw.size) + raw
    }

    private fun encodeHiveInt(value: Long): ByteArray {
        val out = ByteArray(1 + 8)
        out[0] = HIVE_INT_TYPE.toByte()
        ByteBuffer.wrap(out, 1, 8).order(ByteOrder.LITTLE_ENDIAN).putDouble(value.toDouble())
        return out
    }

    private fun decodeHiveStringValue(typedPlaintext: ByteArray): String {
        require(typedPlaintext.size >= 5 && typedPlaintext[0].toInt() == HIVE_STRING_TYPE)
        val length = readLeInt(typedPlaintext, 1)
        require(typedPlaintext.size >= 5 + length)
        return typedPlaintext.copyOfRange(5, 5 + length).toString(StandardCharsets.UTF_8)
    }

    private fun decodeHiveIntValue(typedPlaintext: ByteArray): Long {
        require(typedPlaintext.size >= 9 && typedPlaintext[0].toInt() == HIVE_INT_TYPE)
        return ByteBuffer.wrap(typedPlaintext, 1, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .double
            .toLong()
    }

    private fun readHiveKeyInfo(data: ByteArray, frameOffset: Int, frameLength: Int): HiveKeyInfo? {
        var offset = frameOffset + 4
        val frameValueEnd = frameOffset + frameLength - 4
        if (offset >= frameValueEnd) {
            return null
        }
        val keyType = data[offset].toInt() and 0xFF
        offset += 1
        return when (keyType) {
            0 -> {
                if (offset + 4 > frameValueEnd) return null
                HiveKeyInfo(readLeInt(data, offset).toString(), offset + 4)
            }
            HIVE_KEY_STRING_TYPE -> {
                if (offset >= frameValueEnd) return null
                val keyLength = data[offset].toInt() and 0xFF
                offset += 1
                if (offset + keyLength > frameValueEnd) return null
                HiveKeyInfo(
                    key = data.copyOfRange(offset, offset + keyLength).toString(StandardCharsets.UTF_8),
                    valueOffset = offset + keyLength,
                )
            }
            else -> null
        }
    }

    private fun readLeInt(data: ByteArray, offset: Int): Int {
        return (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun writeLeInt(value: Int): ByteArray {
        return byteArrayOf(
            (value and 0xFF).toByte(),
            ((value ushr 8) and 0xFF).toByte(),
            ((value ushr 16) and 0xFF).toByte(),
            ((value ushr 24) and 0xFF).toByte(),
        )
    }

    private fun hiveCrc32(data: ByteArray, initialCrc: Int): Int {
        var crc = initialCrc xor -0x1
        data.forEach { byte ->
            crc = CRC32_TABLE[(crc xor (byte.toInt() and 0xFF)) and 0xFF] xor (crc ushr 8)
        }
        return crc xor -0x1
    }

    private fun buildCrc32Table(): IntArray {
        return IntArray(256) { seed ->
            var crc = seed
            repeat(8) {
                crc = if ((crc and 1) != 0) {
                    -0x12477ce0 xor (crc ushr 1)
                } else {
                    crc ushr 1
                }
            }
            crc
        }
    }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private data class HiveInspection(
        val validPrefixLength: Int,
        val frameCount: Int,
        val latestLicenseLooksValid: Boolean,
        val latestLicenseDeleted: Boolean,
        val latestLicenseKeyLooksValid: Boolean,
        val latestEmailLooksValid: Boolean,
        val latestOkTimeLooksValid: Boolean,
        val latestFailedCountLooksValid: Boolean,
        val latestAccessTokenLooksValid: Boolean,
    ) {
        val completeForgedState: Boolean
            get() =
                latestLicenseLooksValid &&
                    latestLicenseKeyLooksValid &&
                    latestEmailLooksValid &&
                    latestOkTimeLooksValid &&
                    latestFailedCountLooksValid &&
                    latestAccessTokenLooksValid

        val repairCause: String
            get() = buildList {
                if (latestLicenseDeleted) {
                    add("license_deleted")
                } else if (!latestLicenseLooksValid) {
                    add("license_missing_or_invalid")
                }
                if (!latestLicenseKeyLooksValid) add("license_key")
                if (!latestEmailLooksValid) add("license.email")
                if (!latestOkTimeLooksValid) add("lastCheckOkTime")
                if (!latestFailedCountLooksValid) add("lastCheckFailedCount")
                if (!latestAccessTokenLooksValid) add("accessToken")
                if (validPrefixLength == 0 && frameCount == 0) add("empty_or_unreadable")
            }.joinToString("+").ifBlank { "unknown" }
    }

    private data class HiveKeyInfo(
        val key: String,
        val valueOffset: Int,
    )

    private class RecordingOutputStream(private val connection: Any) : OutputStream() {
        private val buffer = requestBodies.getOrPut(connection) { ByteArrayOutputStream() }

        override fun write(b: Int) {
            if (buffer.size() < MAX_CAPTURE_BYTES) {
                buffer.write(b)
            }
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0 || buffer.size() >= MAX_CAPTURE_BYTES) {
                return
            }
            val allowed = minOf(len, MAX_CAPTURE_BYTES - buffer.size())
            buffer.write(b, off, allowed)
        }

        override fun flush() = Unit

        override fun close() = Unit

        private companion object {
            const val MAX_CAPTURE_BYTES = 16 * 1024
        }
    }

    private data class RequestFields(
        val email: String,
        val licenseKey: String,
        val deviceId: String,
        val orderId: String,
    ) {
        companion object {
            fun from(text: String): RequestFields {
                return RequestFields(
                    email = firstValue(text, "email"),
                    licenseKey = firstValue(text, "license_key", "licenseKey", "key"),
                    deviceId = firstValue(text, "device_id", "deviceId"),
                    orderId = firstValue(text, "order_id", "orderId"),
                )
            }

            private fun firstValue(text: String, vararg keys: String): String {
                if (text.isBlank()) {
                    return ""
                }
                keys.forEach { key ->
                    jsonValue(text, key)?.let { return it }
                    formValue(text, key)?.let { return it }
                }
                return ""
            }

            private fun jsonValue(text: String, key: String): String? {
                val pattern = Regex(""""${Regex.escape(key)}"\s*:\s*"([^"]*)"""")
                return pattern.find(text)?.groupValues?.getOrNull(1)
            }

            private fun formValue(text: String, key: String): String? {
                val pattern = Regex("""(?:^|[&?])${Regex.escape(key)}=([^&]+)""")
                val raw = pattern.find(text)?.groupValues?.getOrNull(1) ?: return null
                return runCatching { URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)
            }
        }
    }
}
