package com.edge.vpn

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "edge_vpn_settings")

/** Persists the single active [EdgeConfig] profile. */
class SettingsStore(private val context: Context) {

    private object Keys {
        val HOST = stringPreferencesKey("host")
        val PORT = intPreferencesKey("port")
        val PATH = stringPreferencesKey("path")
        val SECRET = stringPreferencesKey("secret")
        val SNI = stringPreferencesKey("sni")
        val INSECURE = booleanPreferencesKey("insecure")
    }

    val config: Flow<EdgeConfig> = context.dataStore.data.map { p ->
        val host = p[Keys.HOST] ?: ""
        EdgeConfig(
            host = host,
            port = p[Keys.PORT] ?: 8443,
            tunnelPath = p[Keys.PATH] ?: "/tunnel",
            secret = p[Keys.SECRET] ?: "",
            sni = p[Keys.SNI]?.takeIf { it.isNotBlank() } ?: host,
            allowInsecureTls = p[Keys.INSECURE] ?: false,
        )
    }

    suspend fun save(config: EdgeConfig) {
        context.dataStore.edit { p ->
            p[Keys.HOST] = config.host
            p[Keys.PORT] = config.port
            p[Keys.PATH] = config.tunnelPath
            p[Keys.SECRET] = config.secret
            p[Keys.SNI] = config.sni
            p[Keys.INSECURE] = config.allowInsecureTls
        }
    }
}
