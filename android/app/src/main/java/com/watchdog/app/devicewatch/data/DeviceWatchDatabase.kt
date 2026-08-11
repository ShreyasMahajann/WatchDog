package com.watchdog.app.devicewatch.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * Separate database for the Device Watch tool. Kept apart from the NetScan `watchdog.db` on purpose:
 * that database uses destructive migration, so bumping its version would wipe scan history — a
 * separate file lets the watched-devices schema evolve independently without touching NetScan's data.
 */
@Database(entities = [WatchedDeviceEntity::class], version = 1, exportSchema = false)
abstract class DeviceWatchDatabase : RoomDatabase() {
    abstract fun dao(): DeviceWatchDao

    companion object {
        @Volatile
        private var instance: DeviceWatchDatabase? = null

        fun get(context: Context): DeviceWatchDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    DeviceWatchDatabase::class.java,
                    "watchdog_devicewatch.db",
                ).fallbackToDestructiveMigration().build().also { instance = it }
            }
    }
}
