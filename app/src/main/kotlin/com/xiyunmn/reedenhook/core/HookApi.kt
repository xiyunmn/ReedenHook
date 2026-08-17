package com.xiyunmn.reedenhook.core

import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Executable
import java.lang.reflect.Method

/**
 * Central hook facade. All hooks should go through this object so architecture
 * stays inspectable and classic Xposed APIs never reappear.
 */
object HookApi {
    private const val TAG = "ReedenHook"

    @Volatile
    private var module: XposedModule? = null

    fun attach(value: XposedModule) {
        module = value
    }

    fun detach(value: XposedModule) {
        if (module === value) {
            module = null
        }
    }

    fun i(message: String, tag: String = TAG) {
        Log.i(tag, message)
        module?.log(Log.INFO, tag, message)
    }

    fun w(message: String, tag: String = TAG) {
        Log.w(tag, message)
        module?.log(Log.WARN, tag, message)
    }

    fun e(message: String, tag: String = TAG, throwable: Throwable? = null) {
        if (throwable == null) {
            Log.e(tag, message)
            module?.log(Log.ERROR, tag, message)
        } else {
            Log.e(tag, message, throwable)
            module?.log(Log.ERROR, tag, message, throwable)
        }
    }

    fun d(message: String, tag: String = TAG) {
        Log.d(tag, message)
        module?.log(Log.DEBUG, tag, message)
    }

    fun findClassOrNull(name: String, classLoader: ClassLoader): Class<*>? {
        return runCatching { Class.forName(name, false, classLoader) }.getOrNull()
    }

    fun findDeclaredMethodOrNull(
        clazz: Class<*>,
        name: String,
        vararg parameterTypes: Class<*>,
    ): Method? {
        return runCatching {
            clazz.getDeclaredMethod(name, *parameterTypes).apply {
                isAccessible = true
            }
        }.getOrNull()
    }

    fun interceptProtective(
        module: XposedModule,
        executable: Executable?,
        feature: String,
        id: String? = feature,
        interceptor: (XposedInterface.Chain) -> Any?,
    ): Boolean {
        if (executable == null) {
            w("Skip missing executable: $feature")
            return false
        }
        return runCatching {
            val hooker = XposedInterface.Hooker { chain -> interceptor(chain) }
            val builder = module.hook(executable)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            if (id != null) {
                builder.setId(id)
            }
            builder.intercept(hooker)
            i("Hook installed: $feature" + if (id != null) " id=$id" else "")
            true
        }.getOrElse { throwable ->
            e("Hook failed: $feature", throwable = throwable)
            false
        }
    }

    fun hookAfter(
        module: XposedModule,
        executable: Executable?,
        feature: String,
        id: String? = feature,
        after: (XposedInterface.Chain) -> Unit,
    ): Boolean {
        return interceptProtective(module, executable, feature, id) { chain ->
            val result = chain.proceed()
            after(chain)
            result
        }
    }

    fun hookReturnConstant(
        module: XposedModule,
        executable: Executable?,
        feature: String,
        value: Any?,
        id: String? = feature,
    ): Boolean {
        return interceptProtective(module, executable, feature, id) { value }
    }
}
