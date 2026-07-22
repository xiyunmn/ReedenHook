package com.xiyunmn.reedenhook.host

/**
 * Host package constants for the currently verified Reeden host build.
 * Keep in sync with META-INF/xposed/scope.list.
 */
object HostPackages {
    const val TARGET: String = "app.reeden"
    const val VERSION_NAME: String = "1.37.1"
    const val VERSION_CODE: Int = 694

    fun isTargetPackage(packageName: String): Boolean = packageName == TARGET

    fun isMainProcess(processName: String?): Boolean {
        return processName.isNullOrEmpty() || processName == TARGET
    }

    fun processLabel(processName: String?): String {
        return when {
            processName.isNullOrEmpty() || processName == TARGET -> "main"
            else -> processName
        }
    }
}
