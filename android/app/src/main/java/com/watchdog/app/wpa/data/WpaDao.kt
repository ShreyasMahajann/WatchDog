package com.watchdog.app.wpa.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface WpaDao {

    @Query("SELECT * FROM captures ORDER BY capturedAt DESC")
    fun observeAll(): Flow<List<CaptureEntity>>

    @Query("SELECT * FROM captures WHERE id = :id")
    fun observeById(id: Long): Flow<CaptureEntity?>

    @Query("SELECT * FROM captures WHERE id = :id")
    suspend fun getById(id: Long): CaptureEntity?

    @Query("SELECT * FROM captures WHERE md5 = :md5 LIMIT 1")
    suspend fun findByMd5(md5: String): CaptureEntity?

    @Query("SELECT * FROM captures WHERE status IN ('UPLOADING', 'SUBMITTED')")
    suspend fun submittedCaptures(): List<CaptureEntity>

    /** Insert, ignoring a duplicate MD5 (returns -1 on conflict). */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: CaptureEntity): Long

    @Query(
        """UPDATE captures SET status = :status, statusDetail = :detail,
           submittedAt = COALESCE(:submittedAt, submittedAt),
           lastCheckedAt = COALESCE(:lastCheckedAt, lastCheckedAt),
           password = COALESCE(:password, password)
           WHERE id = :id""",
    )
    suspend fun updateStatus(
        id: Long,
        status: String,
        detail: String?,
        submittedAt: Long?,
        lastCheckedAt: Long?,
        password: String?,
    )

    @Query("DELETE FROM captures WHERE id = :id")
    suspend fun deleteById(id: Long)
}
