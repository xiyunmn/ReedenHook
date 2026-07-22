plugins {
    id("com.android.application") version "9.1.1" apply false
}

tasks.register("verifyArchitecture") {
    group = "verification"
    description = "Checks libxposed API 102 metadata and bans obsolete hook implementations."

    doLast {
        fun sourceFiles(root: java.io.File): Sequence<java.io.File> {
            if (!root.exists()) {
                return emptySequence()
            }
            return root.walkTopDown().filter { file ->
                file.isFile && file.extension.lowercase() in setOf(
                    "java", "kt", "kts", "xml", "list", "prop",
                    "c", "cc", "cpp", "cxx", "h", "hpp", "sh",
                )
            }
        }

        fun entries(file: java.io.File): List<String> {
            return file.readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
        }

        val javaInit = file("app/src/main/resources/META-INF/xposed/java_init.list")
        val expectedEntry = "com.xiyunmn.reedenhook.entry.ReedenHookModule"
        check(entries(javaInit) == listOf(expectedEntry)) {
            "java_init.list must point to $expectedEntry"
        }

        val scope = file("app/src/main/resources/META-INF/xposed/scope.list")
        check(entries(scope) == listOf("app.reeden")) {
            "scope.list must contain only app.reeden"
        }

        val moduleProp = file("app/src/main/resources/META-INF/xposed/module.prop").readText()
        check(moduleProp.contains("minApiVersion=102") && moduleProp.contains("targetApiVersion=102")) {
            "module.prop must target libxposed API 102"
        }
        check(moduleProp.contains("staticScope=true")) {
            "module.prop must set staticScope=true for single-host scope"
        }

        val banned = Regex(
            listOf(
                "de\\.robv\\.android\\.xposed",
                "IXposedHookLoadPackage",
                "XposedBridge",
                "XposedHelpers",
                "assets/xposed_init",
                "\\bxposed_init\\b",
                "io\\.github\\.libxposed:service",
                "androidx\\.compose",
                "androidx\\.activity:activity-compose",
                "de\\.robv\\.android\\.xposed\\.XposedHelpers",
                "HiveForge",
                "Hive license forge",
                "Intercepted Hive\\.get",
            ).joinToString("|"),
            RegexOption.IGNORE_CASE,
        )
        val sourceRoots = listOf(file("app/src"), file("scripts"))
        val matches = sourceRoots.asSequence().flatMap(::sourceFiles).flatMap { source ->
            source.readLines().asSequence().mapIndexedNotNull { index, line ->
                if (banned.containsMatchIn(line)) {
                    "${source.relativeTo(projectDir).invariantSeparatorsPath}:${index + 1}: ${line.trim()}"
                } else {
                    null
                }
            }
        }.toList()
        check(matches.isEmpty()) {
            "Banned legacy/service/compose references found:\n" + matches.take(80).joinToString("\n")
        }

        val obsoleteImplementations = listOf(
            file("app/src/main/cpp/reeden_unlock.cpp"),
            file("scripts/extract_hive_key.sh"),
            file("scripts/test_hive_hook.sh"),
        ).filter(java.io.File::exists)
        check(obsoleteImplementations.isEmpty()) {
            "Obsolete unlock implementations must not be kept in build-facing paths:\n" +
                obsoleteImplementations.joinToString("\n") {
                    it.relativeTo(projectDir).invariantSeparatorsPath
                }
        }
    }
}

gradle.projectsEvaluated {
    tasks.findByPath(":app:preBuild")?.dependsOn(tasks.named("verifyArchitecture"))
}
