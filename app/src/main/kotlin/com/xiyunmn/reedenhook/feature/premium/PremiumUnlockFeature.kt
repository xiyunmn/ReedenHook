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
import java.util.concurrent.atomic.AtomicInteger

/**
 * Local Reeden Pro unlock - single native orchestrator.
 *
 * Strategy v0.4.6:
 * 1. Load native `libreeden_unlock.so`
 * 2. Patch Kwn publication and field_27 gates in the same native install pass
 * 3. Keep Java/Kotlin hooks limited to process lifecycle and native retry orchestration
 *
 * @see local_docs/许可证与网络方案.md
 */
object PremiumUnlockFeature {
    private val probeInstalled = AtomicBoolean(false)
    private val unlockInstalled = AtomicBoolean(false)
    private val nativeRetriesScheduled = AtomicBoolean(false)
    private val active = AtomicBoolean(false)
    private val lifecycleGeneration = AtomicInteger(0)
    private val nativeStateLock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())

    fun install(module: XposedModule, @Suppress("UNUSED_PARAMETER") classLoader: ClassLoader, processName: String) {
        beginInstallCycle()
        HookApi.i(
            "PremiumUnlockFeature.install process=${HostPackages.processLabel(processName)}, " +
                "mode=single_pass_gate_scan (v0.4.6)",
        )

        installApplicationProbe(module)
        scheduleNativeUnlock(reason = "packageReady")
    }

    fun installAfterHotReload(
        module: XposedModule,
        processName: String,
        oldHandles: Collection<XposedInterface.HookHandle>,
    ) {
        beginInstallCycle()
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
        active.set(false)
        lifecycleGeneration.incrementAndGet()
        mainHandler.removeCallbacksAndMessages(null)
        synchronized(nativeStateLock) {
            NativePremiumUnlock.setEnabled(false)
            NativePremiumUnlock.uninstall()
            unlockInstalled.set(false)
        }
        probeInstalled.set(false)
        nativeRetriesScheduled.set(false)
    }

    private fun beginInstallCycle() {
        mainHandler.removeCallbacksAndMessages(null)
        lifecycleGeneration.incrementAndGet()
        nativeRetriesScheduled.set(false)
        active.set(true)
    }

    private fun scheduleNativeUnlock(reason: String) {
        if (!active.get()) {
            return
        }
        if (!nativeRetriesScheduled.compareAndSet(false, true)) {
            return
        }
        // libapp.so may not be mapped at packageReady; one retry ladder is enough
        // for packageReady, attach, and onCreate.
        val generation = lifecycleGeneration.get()
        val delaysMs = longArrayOf(0L, 300L, 800L, 1500L, 3000L, 5000L)
        delaysMs.forEachIndexed { index, delay ->
            mainHandler.postDelayed(
                {
                    if (!active.get() || generation != lifecycleGeneration.get() || unlockInstalled.get()) {
                        return@postDelayed
                    }
                    tryInstallNative(reason = "$reason#$index", generation = generation)
                },
                delay,
            )
        }
    }

    private fun tryInstallNative(reason: String, generation: Int) {
        synchronized(nativeStateLock) {
            if (!active.get() || generation != lifecycleGeneration.get() || unlockInstalled.get()) {
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
            val nativeInstalled = NativePremiumUnlock.isInstalled()
            if (nativeInstalled) {
                unlockInstalled.set(true)
                NativePremiumUnlock.setEnabled(true)
                val message =
                    "Native premium unlock installed ($reason) code=$code " +
                        "status=${NativePremiumUnlock.status()}"
                if (code == 0 || code == 1) {
                    HookApi.i(message)
                } else {
                    // Code 3 is license-only partial success. The native state is
                    // authoritative so hot reload still restores those patches.
                    HookApi.w(message)
                }
            } else {
                unlockInstalled.set(false)
                HookApi.e("Native premium unlock install failed ($reason) code=$code")
            }
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
        ) { chain ->
            HookApi.i("Application.onCreate observed")
            scheduleNativeUnlock(reason = "onCreate")
            val generation = lifecycleGeneration.get()
            mainHandler.postDelayed(
                {
                    if (active.get() && generation == lifecycleGeneration.get()) {
                        HookApi.i("Unlock status: ${NativePremiumUnlock.status()}")
                    }
                },
                4000L,
            )
        }
    }
}
