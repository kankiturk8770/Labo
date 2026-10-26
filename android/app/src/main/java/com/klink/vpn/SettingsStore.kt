package com.klink.vpn

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "klink_settings")

/**
 * The connection profile. The primary, panel-driven flow is a subscription
 * link; the manual fields are an optional fallback when a link is not used.
 */
data class Profile(
    val subUrl: String = "",
    val serverAddr: String = "",
    val sessionHex: String = "",
    val masterHex: String = "",
    val sni: String = "www.aparat.com",
)

class SettingsStore(private val context: Context) {
    private object Keys {
        val SUB = stringPreferencesKey("sub")
        val SERVER = stringPreferencesKey("server")
        val SESSION = stringPreferencesKey("session")
        val MASTER = stringPreferencesKey("master")
        val SNI = stringPreferencesKey("sni")
    }

    val profile: Flow<Profile> = context.dataStore.data.map { p ->
        Profile(
            subUrl = p[Keys.SUB] ?: "",
            serverAddr = p[Keys.SERVER] ?: "",
            sessionHex = p[Keys.SESSION] ?: "",
            masterHex = p[Keys.MASTER] ?: "",
            sni = p[Keys.SNI] ?: "www.aparat.com",
        )
    }

    suspend fun save(profile: Profile) {
        context.dataStore.edit { p ->
            p[Keys.SUB] = profile.subUrl
            p[Keys.SERVER] = profile.serverAddr
            p[Keys.SESSION] = profile.sessionHex
            p[Keys.MASTER] = profile.masterHex
            p[Keys.SNI] = profile.sni
        }
    }
}
