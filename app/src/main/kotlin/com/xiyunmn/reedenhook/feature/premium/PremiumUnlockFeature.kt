package com.xiyunmn.reedenhook.feature.premium

import android.app.Application
import android.content.Context
import android.os.Handler
import android.os.Looper
import com.xiyunmn.reedenhook.core.HookApi
import com.xiyunmn.reedenhook.host.HostAot
import com.xiyunmn.reedenhook.host.HostPackages
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local Reeden Pro unlock - hybrid license publish + feature-gate scanner.
 *
 * Strategy v0.4.1:
 * 1. Load native `libreeden_unlock.so`
 * 2. Scan for Kwn's unique GZc.valid publish sequence and force null/false -> true
 * 3. Scan stable `ldur #0x27; decompress; tbz/tbnz #4` gates and rewrite them
 * 4. License path keeps UI notifier-friendly; gate path unlocks features even
 *    when Kwn does not run on cold start
 *
 * @see local_docs/forged_license_plan.md
 */
object PremiumUnlockFeature {
    private val probeInstalled = AtomicBoolean(false)
    private val unlockInstalled = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())

    fun install(module: XposedModule, @Suppress("UNUSED_PARAMETER") classLoader: ClassLoader, processName: String) {
        HookApi.i(
            "PremiumUnlockFeature.install process=${HostPackages.processLabel(processName)}, " +
                "mode=license_plus_gate_scan (v0.4.1)",
        )

        installApplicationProbe(module)
        scheduleNativeUnlock(reason = "packageReady")
    }

    fun installAfterHotReload(
        module: XposedModule,
        processName: String,
        oldHandles: Collection<XposedInterface.HookHandle>,
    ) {
        HookApi.i(
            "PremiumUnlockFeature.installAfterHotReload process=${HostPackages.processLabel(processName)}, " +
                "oldHandles=${oldHandles.size}",
        )
        probeInstalled.set(false)
        unlockInstalled.set(false)
        installApplicationProbe(module)
        scheduleNativeUnlock(reason = "hotReload")
    }

    fun onHotReloading() {
        HookApi.i("PremiumUnlockFeature.onHotReloading cleanup")
        if (unlockInstalled.get()) {
            NativePremiumUnlock.setEnabled(false)
            NativePremiumUnlock.uninstall()
            unlockInstalled.set(false)
        }
        probeInstalled.set(false)
    }


    private fun scheduleNativeUnlock(reason: String) {
        // libapp.so may not be mapped at packageReady; retry a few times.
        val delaysMs = longArrayOf(0L, 300L, 800L, 1500L, 3000L, 5000L)
        delaysMs.forEachIndexed { index, delay ->
            mainHandler.postDelayed(
                {
                    if (unlockInstalled.get()) {
                        return@postDelayed
                    }
                    tryInstallNative(reason = "$reason#$index")
                },
                delay,
            )
        }
    }

    private fun tryInstallNative(reason: String) {
        if (unlockInstalled.get()) {
            return
        }
        if (!isLibAppLoaded()) {
            HookApi.w("tryInstallNative($reason): ${HostAot.LIB_APP} not mapped yet")
            return
        }
        if (!NativePremiumUnlock.ensureLoaded()) {
            HookApi.e("tryInstallNative($reason): native library load failed")
            return
        }
        val code = NativePremiumUnlock.install()
        // 0 = full success, 1 = soft success (gates only / license soft-miss)
        if (code == 0 || code == 1) {
            unlockInstalled.set(true)
            NativePremiumUnlock.setEnabled(true)
            HookApi.i(
                "Native premium unlock installed ($reason) code=$code status=${NativePremiumUnlock.status()}",
            )
        } else {
            HookApi.e("Native premium unlock install failed ($reason) code=$code")
        }
    }

    private fun isLibAppLoaded(): Boolean {
        return runCatching {
            val maps = java.io.File("/proc/self/maps").readText()
            maps.contains(HostAot.LIB_APP)
        }.getOrDefault(false)
    }


    private fun installApplicationProbe(module: XposedModule) {
        if (!probeInstalled.compareAndSet(false, true)) {
            return
        }

        val attach = HookApi.findDeclaredMethodOrNull(
            Application::class.java,
            "attach",
            Context::class.java,
        )
        HookApi.hookAfter(
            module = module,
            executable = attach,
            feature = "Application.attach.premiumProbe",
            id = "premium.Application.attach",
        ) { chain ->
            val context = chain.getArg(0) as? Context
            HookApi.i(
                "Application.attach observed: package=${context?.packageName}",
            )
            scheduleNativeUnlock(reason = "attach")
        }

        val onCreate = HookApi.findDeclaredMethodOrNull(Application::class.java, "onCreate")
        HookApi.hookAfter(
            module = module,
            executable = onCreate,
            feature = "Application.onCreate.premiumProbe",
            id = "premium.Application.onCreate",
        ) {
            HookApi.i("Application.onCreate observed")
            scheduleNativeUnlock(reason = "onCreate")
            mainHandler.postDelayed(
                {
                    HookApi.i("Unlock status: ${NativePremiumUnlock.status()}")
                },
                4000L,
            )
        }
    }
}
