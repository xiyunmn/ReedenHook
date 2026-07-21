# Keep the libxposed entry point referenced from META-INF/xposed/java_init.list.
-dontwarn io.github.libxposed.annotation.**
-dontwarn io.github.libxposed.api.**

-adaptresourcefilecontents META-INF/xposed/java_init.list

-keep,allowoptimization,allowobfuscation public class * extends io.github.libxposed.api.XposedModule {
    public <init>();
}

-keep class com.xiyunmn.reedenhook.entry.ReedenHookModule {
    public <init>();
}

# Host package / AOT offset constants used by premium feature stubs.
-keep class com.xiyunmn.reedenhook.host.** { *; }
-keep class com.xiyunmn.reedenhook.feature.premium.** { *; }

# JNI bridge for native unlock.
-keep class com.xiyunmn.reedenhook.feature.premium.NativePremiumUnlock {
    *;
}
