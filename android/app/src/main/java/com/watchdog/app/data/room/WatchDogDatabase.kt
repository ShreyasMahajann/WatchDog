package com.watchdog.app.data.room

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        NetworkEntity::class,
        ScanEntity::class,
        HostEntity::class,
        PortEntity::class,
        ServiceEntity::class,
        FingerprintEntity::class,
        FindingEntity::class,
    ],
    version = 2,
    exportSchema = false,
)
abstract class WatchDogDatabase : RoomDatabase() {
    abstract fun dao(): WatchDogDao

    companion object {
        @Volatile
        private var instance: WatchDogDatabase? = null

        fun get(context: Context): WatchDogDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    WatchDogDatabase::class.java,
                    "watchdog.db",
                ).fallbackToDestructiveMigration().build().also { instance = it }
            }
    }
}
