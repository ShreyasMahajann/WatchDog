package com.watchdog.app.wpa.device

import java.io.File
import java.util.concurrent.TimeUnit

/** Small shared helpers for locating and running command-line tools. */
internal object Shell {

    /** Result of running a short command: exit code (-1 if it never completed) and combined output. */
    data class Output(val exitCode: Int, val text: String, val timedOut: Boolean)

    /** Directories on the process PATH, plus the usual Android bin dirs as a fallback. */
    private fun searchDirs(): List<String> {
        val fromPath = (System.getenv("PATH") ?: "").split(File.pathSeparatorChar).filter { it.isNotBlank() }
        val defaults = listOf("/system/bin", "/system/xbin", "/vendor/bin", "/sbin", "/su/bin")
        return (fromPath + defaults).distinct()
    }

    /** Absolute path to [cmd] if it exists on the search path, else null. */
    fun which(cmd: String): String? =
        searchDirs().map { File(it, cmd) }
            .firstOrNull { runCatching { it.exists() }.getOrDefault(false) }
            ?.absolutePath

    /**
     * Run [args] with a hard [timeoutMs] budget so a hung `su`/`iw` never blocks the UI.
     * Returns combined stdout+stderr. Never throws — failures come back as a non-zero exit.
     */
    fun run(args: List<String>, timeoutMs: Long = 4_000): Output = try {
        val proc = ProcessBuilder(args).redirectErrorStream(true).start()
        val finished = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) {
            proc.destroy()
            Output(exitCode = -1, text = proc.readAllText(), timedOut = true)
        } else {
            Output(exitCode = proc.exitValue(), text = proc.readAllText(), timedOut = false)
        }
    } catch (t: Throwable) {
        Output(exitCode = -1, text = t.message ?: t.javaClass.simpleName, timedOut = false)
    }

    private fun Process.readAllText(): String =
        runCatching { inputStream.bufferedReader().readText() }.getOrDefault("")
}
