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
 * Small append-only file logger for the host process.
 *
 * Primary sink:
 *   /data/user/<user>/app.reeden/files/reedenhook/logs/reedenhook.log
 *
 * Mirror sink, when Android exposes it:
 *   /sdcard/Android/data/app.reeden/files/reedenhook/logs/reedenhook.log
 */
object HostFileLogger {
    private const val RELATIVE_LOG_PATH = "reedenhook/logs/reedenhook.log"
    private const val MAX_LOG_BYTES = 512 * 1024L
    private const val MAX_PENDING_LINES = 256
    private const val MAX_LINE_CHARS = 8_000

    private val lock = Any()
    private val pendingLines = ArrayDeque<String>()
    private val dateFormat = ThreadLocal.withInitial {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    }
    private val sinks = ArrayList<File>(2)

    @Volatile
    private var currentPaths = Paths(privatePath = null, externalPath = null, changed = false)

    data class Paths(
        val privatePath: String?,
        val externalPath: String?,
        val changed: Boolean,
    )

    fun configure(context: Context, reason: String): Paths {
        val privateFile = runCatching { File(context.filesDir, RELATIVE_LOG_PATH) }.getOrNull()
        val externalFile = runCatching {
            context.getExternalFilesDir(null)?.let { File(it, RELATIVE_LOG_PATH) }
        }.getOrNull()
        val nextSinks = listOfNotNull(privateFile, externalFile).distinctBy { it.absolutePath }
        val nextSignature = nextSinks.joinToString("|") { it.absolutePath }

        synchronized(lock) {
            val changed = nextSignature != sinks.joinToString("|") { it.absolutePath }
            if (changed) {
                sinks.clear()
                sinks.addAll(nextSinks)
            }
            currentPaths = Paths(
                privatePath = privateFile?.absolutePath,
                externalPath = externalFile?.absolutePath,
                changed = changed,
            )

            if (sinks.isNotEmpty()) {
                while (!pendingLines.isEmpty()) {
                    appendLineLocked(pendingLines.removeFirst())
                }
                appendLineLocked(
                    formatLine(
                        priority = Log.INFO,
                        tag = "ReedenHook.FileLog",
                        message = "configured reason=$reason private=${privateFile?.absolutePath} " +
                            "external=${externalFile?.absolutePath ?: "n/a"}",
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
        val backup = File(file.parentFile, "${file.name}.1")
        runCatching {
            if (backup.exists()) {
                backup.delete()
            }
            file.renameTo(backup)
        }
    }
}
