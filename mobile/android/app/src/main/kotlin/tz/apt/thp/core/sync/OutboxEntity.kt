package tz.apt.thp.core.sync

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Pending outbound action that survives process death and network drops.
 * Created when the user takes an action (ack, post note, fleet command);
 * removed when the server returns 2xx; abandoned on 4xx other than 408/429.
 *
 * `payloadJson` is the EXACT body to POST — pre-resolved at enqueue time so
 * the worker never has to re-derive it. `targetUrlSuffix` is the path part
 * only ("/alerts/abc/acknowledge"); the worker prepends the server URL from
 * the current session so a re-pair to a new server doesn't break the queue.
 */
@Entity(tableName = "outbox")
data class OutboxEntity(
    @PrimaryKey val id: String,
    val kind: String,                  // "ack" | "note" | "fleet_cmd"
    val targetUrlSuffix: String,       // e.g. "/alerts/{id}/notes"
    val method: String,                // "POST" | "DELETE"
    val payloadJson: String,           // raw JSON body, may be ""
    val createdAt: Long,
    val attempts: Int = 0,
    val nextAttemptAt: Long = 0L,
    val lastError: String? = null,
    val terminal: Boolean = false,     // true once we give up — shown in failed list
)

/** Kind constants — strings exposed to the user via UI copy. */
object OutboxKind {
    const val ACK       = "ack"
    const val NOTE      = "note"
    const val FLEET_CMD = "fleet_cmd"
}
