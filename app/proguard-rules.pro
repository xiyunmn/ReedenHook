# Keep only the framework/JNI names that are resolved outside normal bytecode.
-dontwarn io.github.libxposed.annotation.**
-dontwarn io.github.libxposed.api.**

-adaptresourcefilecontents META-INF/xposed/java_init.list

-keep,allowoptimization class com.xiyunmn.reedenhook.entry.ReedenHookModule {
    public <init>();
}

# Static JNI exports in libreeden_unlock.so use these exact class and method names.
-keep,allowoptimization class com.xiyunmn.reedenhook.feature.premium.NativePremiumUnlock {
    private native <methods>;
}

-keep,allowoptimization class com.xiyunmn.reedenhook.feature.premium.NativeNetworkGuard {
    private native <methods>;
}
