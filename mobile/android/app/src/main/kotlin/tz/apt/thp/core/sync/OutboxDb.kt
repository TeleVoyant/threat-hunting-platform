package tz.apt.thp.core.sync

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [OutboxEntity::class], version = 1, exportSchema = false)
abstract class OutboxDb : RoomDatabase() {
    abstract fun outboxDao(): OutboxDao

    companion object {
        @Volatile private var instance: OutboxDb? = null

        fun get(ctx: Context): OutboxDb = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                ctx.applicationContext, OutboxDb::class.java, "apt-outbox.db",
            ).fallbackToDestructiveMigration().build().also { instance = it }
        }
    }
}
