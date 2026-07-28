package com.xiyunmn.reedenhook.feature.premium

import com.xiyunmn.reedenhook.core.HostFileLogger
import com.xiyunmn.reedenhook.core.HookApi

/**
 * JNI bridge for the network-first guard.
 *
 * This only hooks Flutter's imported getaddrinfo in libflutter.so for Reeden's
 * license hosts. It intentionally does not invoke the older Dart AOT gate patch
 * installer exposed by [NativePremiumUnlock].
 */
object NativeNetworkGuard {
    private const val TAG = "ReedenHook.Network"

    @Volatile
    private var libraryLoaded: Boolean = false

    @Volatile
    private var loadError: String? = null

    @Volatile
    private var privateLogPath: String? = null

    @Volatile
    private var appliedLogSignature: String? = null

    fun ensureLoaded(): Boolean {
        if (libraryLoaded) {
            return true
        }
        synchronized(this) {
            if (libraryLoaded) {
                return true
            }
            return runCatching {
                System.loadLibrary("reeden_unlock")
                libraryLoaded = true
                loadError = null
                applyFileLogPaths()
                HookApi.i("NativeNetworkGuard library loaded", TAG)
                true
            }.getOrElse { throwable ->
                loadError = throwable.message ?: throwable.javaClass.name
                HookApi.e("NativeNetworkGuard load failed: $loadError", TAG, throwable)
                false
            }
        }
    }

    fun configureFileLogging(paths: HostFileLogger.Paths) {
        privateLogPath = paths.privatePath
        if (libraryLoaded) {
            applyFileLogPaths()
        }
    }

    fun install(reason: String): Int {
        if (!ensureLoaded()) {
            return -100
        }
        applyFileLogPaths()
        return runCatching {
            val code = nativeInstall()
            HookApi.i("NativeNetworkGuard install reason=$reason code=$code status=${status()}", TAG)
            code
        }.getOrElse { throwable ->
            HookApi.e("NativeNetworkGuard install failed reason=$reason", TAG, throwable)
            -101
        }
    }

    fun setEnabled(enabled: Boolean) {
        if (!libraryLoaded) {
            return
        }
        runCatching { nativeSetEnabled(enabled) }
            .onFailure { HookApi.e("NativeNetworkGuard setEnabled failed", TAG, it) }
    }

    fun isInstalled(): Boolean {
        if (!libraryLoaded) {
            return false
        }
        return runCatching { nativeIsInstalled() }.getOrDefault(false)
    }

    fun status(): String {
        if (!libraryLoaded) {
            return "library not loaded: ${loadError ?: "n/a"}"
        }
        return runCatching { nativeStatus() }.getOrDefault("status unavailable")
    }

    private fun applyFileLogPaths() {
        if (!libraryLoaded) {
            return
        }
        val signature = privateLogPath.orEmpty()
        if (appliedLogSignature == signature) {
            return
        }
        runCatching { nativeSetFileLogPaths(privateLogPath, null) }
            .onSuccess { appliedLogSignature = signature }
            .onFailure { HookApi.e("NativeNetworkGuard file log config failed", TAG, it) }
    }

    private external fun nativeInstall(): Int
    private external fun nativeSetEnabled(enabled: Boolean)
    private external fun nativeIsInstalled(): Boolean
    private external fun nativeStatus(): String
    private external fun nativeSetFileLogPaths(privatePath: String?, externalPath: String?)
}
