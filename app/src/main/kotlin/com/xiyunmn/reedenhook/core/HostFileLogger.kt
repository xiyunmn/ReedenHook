package com.xiyunmn.reedenhook.core

import android.content.Context
import android.os.Process
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * Small rotating file logger for the host process private directory.
 */
object HostFileLogger {
    private const val RELATIVE_LOG_PATH = "reedenhook/logs/reedenhook.log"
    private const val MAX_LOG_BYTES = 256 * 1024L
    private const val MAX_LOG_FILES = 3
    private const val MAX_PENDING_LINES = 256
    private const val MAX_LINE_CHARS = 8_000

    private val lock = Any()
    private val pendingLines = ArrayDeque<String>()
    private val dateFormat = ThreadLocal.withInitial {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    }
    private val sinks = ArrayList<File>(1)

    @Volatile
    private var currentPaths = Paths(privatePath = null, externalPath = null, changed = false)

    data class Paths(
        val privatePath: String?,
        val externalPath: String?,
        val changed: Boolean,
    )

    fun configure(context: Context, reason: String): Paths {
        val privateFile = runCatching { File(context.filesDir, RELATIVE_LOG_PATH) }.getOrNull()
        val nextSinks = listOfNotNull(privateFile).distinctBy { it.absolutePath }
        val nextSignature = nextSinks.joinToString("|") { it.absolutePath }

        synchronized(lock) {
            val changed = nextSignature != sinks.joinToString("|") { it.absolutePath }
            if (changed) {
                sinks.clear()
                sinks.addAll(nextSinks)
            }
            currentPaths = Paths(
                privatePath = privateFile?.absolutePath,
                externalPath = null,
                changed = changed,
            )

            if (sinks.isNotEmpty()) {
                sinks.forEach(::cleanupExcessRotatedFiles)
                while (!pendingLines.isEmpty()) {
                    appendLineLocked(pendingLines.removeFirst())
                }
                appendLineLocked(
                    formatLine(
                        priority = Log.INFO,
                        tag = "ReedenHook.FileLog",
                        message = "configured reason=$reason private=${privateFile?.absolutePath} " +
                            "maxBytes=$MAX_LOG_BYTES maxFiles=$MAX_LOG_FILES",
                    ),
                )
            }
            return currentPaths
        }
    }

    fun currentPaths(): Paths = currentPaths

    fun log(priority: Int, tag: String, message: String, throwable: Throwable? = null) {
        val combined = if (throwable == null) {
            message
        } else {
            message + "\n" + Log.getStackTraceString(throwable)
        }
        val lines = combined.lineSequence()
            .ifEmpty { sequenceOf("") }
            .map { line ->
                formatLine(
                    priority = priority,
                    tag = tag,
                    message = if (line.length <= MAX_LINE_CHARS) {
                        line
                    } else {
                        line.take(MAX_LINE_CHARS) + " ...<truncated>"
                    },
                )
            }
            .toList()

        synchronized(lock) {
            lines.forEach { line ->
                if (sinks.isEmpty()) {
                    pendingLines.addLast(line)
                    while (pendingLines.size > MAX_PENDING_LINES) {
                        pendingLines.removeFirst()
                    }
                } else {
                    appendLineLocked(line)
                }
            }
        }
    }

    private fun formatLine(priority: Int, tag: String, message: String): String {
        val timestamp = dateFormat.get()?.format(Date()) ?: Date().time.toString()
        val level = when (priority) {
            Log.ERROR -> "E"
            Log.WARN -> "W"
            Log.INFO -> "I"
            Log.DEBUG -> "D"
            Log.VERBOSE -> "V"
            else -> priority.toString()
        }
        return "$timestamp $level/$tag(${Process.myPid()}:${Process.myTid()}): $message\n"
    }

    private fun appendLineLocked(line: String) {
        val bytes = line.toByteArray(StandardCharsets.UTF_8)
        sinks.forEach { sink ->
            runCatching {
                val parent = sink.parentFile
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    return@runCatching
                }
                rotateIfNeeded(sink, bytes.size.toLong())
                FileOutputStream(sink, true).use { out ->
                    out.write(bytes)
                }
            }
        }
    }

    private fun rotateIfNeeded(file: File, incomingBytes: Long) {
        if (!file.exists() || file.length() + incomingBytes <= MAX_LOG_BYTES) {
            return
        }
        val parent = file.parentFile ?: return
        runCatching {
            cleanupExcessRotatedFiles(file)
            for (index in (MAX_LOG_FILES - 1) downTo 1) {
                val source = if (index == 1) {
                    file
                } else {
                    File(parent, "${file.name}.${index - 1}")
                }
                val target = File(parent, "${file.name}.$index")
                if (!source.exists()) {
                    continue
                }
                if (target.exists()) {
                    target.delete()
                }
                source.renameTo(target)
            }
        }
    }

    private fun cleanupExcessRotatedFiles(file: File) {
        val parent = file.parentFile ?: return
        runCatching {
            parent.listFiles { candidate ->
                val suffix = candidate.name.removePrefix("${file.name}.")
                candidate.isFile &&
                    candidate.name.startsWith("${file.name}.") &&
                    suffix.toIntOrNull()?.let { it >= MAX_LOG_FILES } == true
            }?.forEach { it.delete() }
        }
    }
}
