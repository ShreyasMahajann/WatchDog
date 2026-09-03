package com.watchdog.desktop.data

import java.io.File

/** Where the desktop app keeps its data (settings, database, captures). */
object AppDirs {
    fun dataDir(): File {
        val os = System.getProperty("os.name")?.lowercase().orEmpty()
        val home = System.getProperty("user.home") ?: "."
        val base = when {
            os.contains("win") -> System.getenv("LOCALAPPDATA")?.let { File(it) } ?: File(home, "AppData/Local")
            else -> System.getenv("XDG_DATA_HOME")?.let { File(it) } ?: File(home, ".local/share")
        }
        return File(base, "watchDog").apply { mkdirs() }
    }

    fun capturesDir(): File = File(dataDir(), "captures").apply { mkdirs() }
}
