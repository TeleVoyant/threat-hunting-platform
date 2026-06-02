package tz.apt.thp.core.sync

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface OutboxDao {

    /** Live count for the pending-pill in the topbar. */
    @Query("SELECT COUNT(*) FROM outbox WHERE terminal = 0")
    fun pendingCount(): Flow<Int>

    @Query("SELECT * FROM outbox ORDER BY createdAt ASC")
    fun all(): Flow<List<OutboxEntity>>

    @Query("SELECT * FROM outbox WHERE terminal = 0 AND nextAttemptAt <= :nowMs ORDER BY createdAt ASC LIMIT 1")
    suspend fun nextDue(nowMs: Long): OutboxEntity?

    @Query("SELECT * FROM outbox WHERE terminal = 0")
    suspend fun allPending(): List<OutboxEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: OutboxEntity)

    @Update
    suspend fun update(entity: OutboxEntity)

    @Query("DELETE FROM outbox WHERE id = :id")
    suspend fun delete(id: String)

    @Query("DELETE FROM outbox WHERE terminal = 1")
    suspend fun clearTerminal()

    /**
     * Wipe every row. Called during unpair so a pending ack / note /
     * fleet-command from the previous identity can't be replayed against a
     * new pairing's credentials (otherwise the audit trail would attribute
     * the old user's action to the new one).
     */
    @Query("DELETE FROM outbox")
    suspend fun clearAll()
}
