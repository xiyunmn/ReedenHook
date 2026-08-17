package com.xiyunmn.reedenhook.feature.premium

import android.content.Context
import com.xiyunmn.reedenhook.core.HookApi
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Modifier
import java.util.concurrent.atomic.AtomicInteger

/** Neutralizes the runtime-integrity report introduced by Reeden 1.38.1. */
object RuntimeIntegrityOverrideFeature {
    private const val TAG = "ReedenHook.Integrity"
    private const val REPORTER_CLASS = "app.reeden.R0"
    private val hits = AtomicInteger(0)

    fun install(module: XposedModule, classLoader: ClassLoader): Boolean {
        val reporter = HookApi.findClassOrNull(REPORTER_CLASS, classLoader)
        if (reporter == null) {
            HookApi.w("Runtime report class not found: $REPORTER_CLASS", TAG)
            return false
        }

        val candidates = reporter.declaredMethods.filter { method ->
            !Modifier.isStatic(method.modifiers) &&
                Map::class.java.isAssignableFrom(method.returnType) &&
                method.parameterTypes.contentEquals(arrayOf(Context::class.java))
        }
        if (candidates.size != 1) {
            HookApi.w(
                "Runtime report method match count=${candidates.size} class=$REPORTER_CLASS",
                TAG,
            )
            return false
        }

        val method = candidates.single().apply { isAccessible = true }
        return HookApi.interceptProtective(
            module = module,
            executable = method,
            feature = "RuntimeIntegrity.cleanReport",
            id = "integrity.${reporter.name}.${method.name}",
        ) {
            val count = hits.incrementAndGet()
            if (count == 1 || count % 20 == 0) {
                HookApi.i("Runtime report override hit #$count", TAG)
            }
            cleanReport()
        }
    }

    private fun cleanReport(): Map<String, Any> {
        return linkedMapOf(
            "a" to false,
            "i" to listOf(false, false, false),
            "n" to linkedMapOf(
                "a" to false,
                "m" to false,
                "h" to false,
            ),
        )
    }
}
