package com.xiyunmn.reedenhook.feature.premium

import com.xiyunmn.reedenhook.core.HookApi

/**
 * JNI bridge to arm64 native unlock in `libreeden_unlock.so`.
 *
 * Hybrid strategy: license-publication scan + field_27 gate pattern scan.
 * Dart AOT must not be intercepted with standard ABI trampolines (uses x15 as SP).
 */
object NativePremiumUnlock {
    @Volatile
    private var libraryLoaded: Boolean = false

    @Volatile
    private var loadError: String? = null

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
                HookApi.i("NativePremiumUnlock library loaded")
                true
            }.getOrElse { throwable ->
                loadError = throwable.message ?: throwable.javaClass.name
                HookApi.e("NativePremiumUnlock load failed: $loadError", throwable = throwable)
                false
            }
        }
    }

    fun install(): Int {
        if (!ensureLoaded()) {
            return -100
        }
        return runCatching { nativeInstall() }
            .getOrElse { throwable ->
                HookApi.e("nativeInstall failed", throwable = throwable)
                -101
            }
    }

    fun uninstall() {
        if (!libraryLoaded) {
            return
        }
        runCatching { nativeUninstall() }
            .onFailure { HookApi.e("nativeUninstall failed", throwable = it) }
    }

    fun setEnabled(enabled: Boolean) {
        if (!libraryLoaded) {
            return
        }
        runCatching { nativeSetEnabled(enabled) }
            .onFailure { HookApi.e("nativeSetEnabled failed", throwable = it) }
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

    private external fun nativeInstall(): Int
    private external fun nativeUninstall()
    private external fun nativeSetEnabled(enabled: Boolean)
    private external fun nativeIsInstalled(): Boolean
    private external fun nativeStatus(): String
}
