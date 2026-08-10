package com.watchdog.app.wpa.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * Separate database for the WPA tool. Kept apart from the NetScan `watchdog.db` on purpose: that
 * database uses destructive migration, so bumping its version would wipe scan history — a separate
 * file lets the WPA schema evolve independently without touching NetScan's data.
 */
@Database(entities = [CaptureEntity::class], version = 1, exportSchema = false)
abstract class WpaDatabase : RoomDatabase() {
    abstract fun dao(): WpaDao

    companion object {
        @Volatile
        private var instance: WpaDatabase? = null

        fun get(context: Context): WpaDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    WpaDatabase::class.java,
                    "watchdog_wpa.db",
                ).fallbackToDestructiveMigration().build().also { instance = it }
            }
    }
}
