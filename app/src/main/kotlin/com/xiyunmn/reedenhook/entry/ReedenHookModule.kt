package com.xiyunmn.reedenhook.entry

import android.util.Log
import com.xiyunmn.reedenhook.core.HookApi
import com.xiyunmn.reedenhook.feature.premium.NetworkLicenseOverrideFeature
import com.xiyunmn.reedenhook.host.HostAot
import com.xiyunmn.reedenhook.host.HostPackages
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.HotReloadedParam
import io.github.libxposed.api.XposedModuleInterface.HotReloadingParam
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Modern libxposed API 102 entry for Reeden (app.reeden).
 *
 * Competition mode is network-first: install only the Java URL/HTTP response
 * override path and keep native Dart AOT patching out of the active hook graph.
 */
class ReedenHookModule : XposedModule() {
    private var processName: String = ""
    private var hostClassLoader: ClassLoader? = null
    private val installed = AtomicBoolean(false)

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        HookApi.attach(this)
        processName = param.processName
        log(
            Log.INFO,
            TAG,
            "Module loaded: process=$processName, api=$apiVersion, " +
                "host=${HostPackages.TARGET} ${HostPackages.VERSION_NAME}",
        )
    }

    override fun onPackageLoaded(param: PackageLoadedParam) {
        if (!HostPackages.isTargetPackage(param.packageName)) {
            return
        }
        HookApi.i(
            "Target package loaded: package=${param.packageName}, " +
                "process=${HostPackages.processLabel(processName)}, first=${param.isFirstPackage}",
        )
    }

    override fun onPackageReady(param: PackageReadyParam) {
        if (!HostPackages.isTargetPackage(param.packageName)) {
            return
        }
        if (!param.isFirstPackage) {
            HookApi.w("Skip secondary package callback: ${param.packageName}")
            return
        }
        if (!HostPackages.isMainProcess(processName)) {
            HookApi.i("Skip non-main process: $processName")
            return
        }
        if (!installed.compareAndSet(false, true)) {
            HookApi.w("Features already installed in this process")
            return
        }

        HookApi.i(
            "Target ready: package=${param.packageName}, process=$processName, " +
                "classLoader=${param.classLoader}, dartBaseline=${HostAot.DART_VERSION}, mode=network_response_override",
        )
        hostClassLoader = param.classLoader
        NetworkLicenseOverrideFeature.install(this, param.classLoader, processName)
    }

    override fun onHotReloading(param: HotReloadingParam): Boolean {
        HookApi.i(
            "Hot reload requested: process=${HostPackages.processLabel(processName)}, " +
                "installed=${installed.get()}",
        )
        NetworkLicenseOverrideFeature.onHotReloading()
        installed.set(false)
        HookApi.detach(this)
        return true
    }

    override fun onHotReloaded(param: HotReloadedParam) {
        HookApi.attach(this)
        processName = param.processName
        HookApi.i(
            "Hot reloaded: process=${HostPackages.processLabel(processName)}, " +
                "oldHandles=${param.oldHookHandles.size}",
        )
        // Re-install happens on next package-ready style path if host re-invokes;
        // for API 102 hot reload we re-run feature install when still in target process.
        if (HostPackages.isMainProcess(processName) && installed.compareAndSet(false, true)) {
            val classLoader = hostClassLoader ?: ReedenHookModule::class.java.classLoader
            if (classLoader == null) {
                HookApi.e("Hot reload skipped: missing classLoader")
            } else {
                NetworkLicenseOverrideFeature.installAfterHotReload(
                    this,
                    classLoader,
                    processName,
                    param.oldHookHandles,
                )
            }
        }
    }

    private companion object {
        const val TAG = "ReedenHook.Module"
    }
}
