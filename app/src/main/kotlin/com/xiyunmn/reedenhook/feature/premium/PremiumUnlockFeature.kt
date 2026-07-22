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
 * Local Reeden Pro unlock - cached license publish + feature-gate scanner.
 *
 * Strategy v0.4.1:
 * 1. Load native `libreeden_unlock.so`
 * 2. Publish an encrypted local license cache from inside app.reeden
 * 3. Scan for Kwn's unique GZc.valid publish sequence and force null/false -> true
 * 4. Scan stable `ldur #0x27; decompress; tbz/tbnz #4` gates and rewrite them
 * 5. License path keeps UI notifier-friendly; gate path unlocks features even
 *    when Kwn does not run on cold start
 *
 * @see local_docs/forged_license_plan.md
 */
object PremiumUnlockFeature {
    private val probeInstalled = AtomicBoolean(false)
    private val unlockInstalled = AtomicBoolean(false)
    private val licenseMaintenanceInstalled = AtomicBoolean(false)
    private val active = AtomicBoolean(false)
    private val lifecycleGeneration = AtomicInteger(0)
    private val nativeStateLock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())

    fun install(module: XposedModule, @Suppress("UNUSED_PARAMETER") classLoader: ClassLoader, processName: String) {
        beginInstallCycle()
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
        licenseMaintenanceInstalled.set(false)
    }

    private fun beginInstallCycle() {
        mainHandler.removeCallbacksAndMessages(null)
        lifecycleGeneration.incrementAndGet()
        active.set(true)
    }

    private fun scheduleNativeUnlock(reason: String) {
        if (!active.get()) {
            return
        }
        // libapp.so may not be mapped at packageReady; retry a few times.
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
            scheduleLicensePublish(context, reason = "attach")
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
            scheduleLicensePublish(chain.getThisObject() as? Context, reason = "onCreate")
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

    private fun scheduleLicensePublish(context: Context?, reason: String) {
        if (context == null || !HostPackages.isTargetPackage(context.packageName)) {
            return
        }
        val appContext = context.applicationContext ?: context
        val generation = lifecycleGeneration.get()
        val delaysMs = longArrayOf(0L, 400L, 1200L, 2500L, 5000L, 10000L, 20000L, 45000L)
        delaysMs.forEachIndexed { index, delay ->
            mainHandler.postDelayed(
                {
                    if (active.get() && generation == lifecycleGeneration.get()) {
                        LicenseCachePublisher.requestPublish(appContext, "$reason#$index")
                    }
                },
                delay,
            )
        }
        scheduleLicenseMaintenance(appContext, generation)
    }

    private fun scheduleLicenseMaintenance(context: Context, generation: Int) {
        if (!licenseMaintenanceInstalled.compareAndSet(false, true)) {
            return
        }
        fun postNext() {
            mainHandler.postDelayed(
                {
                    if (active.get() && generation == lifecycleGeneration.get()) {
                        LicenseCachePublisher.requestPublish(context, "maintenance")
                        postNext()
                    } else {
                        licenseMaintenanceInstalled.set(false)
                    }
                },
                60_000L,
            )
        }
        postNext()
    }
}
