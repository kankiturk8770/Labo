package com.klink.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var store: SettingsStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = SettingsStore(applicationContext)
        setContent { KlinkTheme { AppScreen(store, ::launchVpn, ::stopVpn) } }
    }

    private fun launchVpn() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else startVpn()
    }

    private fun startVpn() {
        startService(Intent(this, KlinkVpnService::class.java))
    }

    private fun stopVpn() {
        startService(Intent(this, KlinkVpnService::class.java).setAction(KlinkVpnService.ACTION_STOP))
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpn()
            else TunnelState.set(Stage.ERROR, "VPN permission denied")
        }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppScreen(store: SettingsStore, onConnect: () -> Unit, onDisconnect: () -> Unit) {
    val scope = rememberCoroutineScope()
    val status by TunnelState.status.collectAsState()

    var sub by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("") }
    var session by remember { mutableStateOf("") }
    var master by remember { mutableStateOf("") }
    var sni by remember { mutableStateOf("www.aparat.com") }
    var loaded by remember { mutableStateOf(false) }

    if (!loaded) {
        scope.launch {
            val p = store.profile.first()
            sub = p.subUrl; server = p.serverAddr; session = p.sessionHex
            master = p.masterHex; sni = p.sni; loaded = true
        }
    }

    fun current() = Profile(sub.trim(), server.trim(), session.trim(), master.trim(), sni.trim().ifBlank { "www.aparat.com" })

    Scaffold(topBar = { TopAppBar(title = { Text("KLINK VPN") }) }) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).fillMaxSize().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Card(
                Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(status.stage.name, style = MaterialTheme.typography.titleMedium)
                    if (status.message.isNotBlank()) {
                        Text(status.message, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }

            Text("لینک سابسکریپشن از پنل (توصیه‌شده)", style = MaterialTheme.typography.labelLarge)
            OutlinedTextField(sub, { sub = it }, label = { Text("https://SERVER:8443/sub/TOKEN") },
                singleLine = true, modifier = Modifier.fillMaxWidth())

            Text("یا تنظیم دستی", style = MaterialTheme.typography.labelLarge)
            OutlinedTextField(server, { server = it }, label = { Text("Server (host:port)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(session, { session = it }, label = { Text("Session ID (hex)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(master, { master = it }, label = { Text("Master Key (hex)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(sni, { sni = it }, label = { Text("SNI (mimic domain)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                val active = status.stage == Stage.CONNECTED || status.stage == Stage.CONNECTING
                if (active) {
                    Button(onClick = onDisconnect) { Text("قطع اتصال") }
                } else {
                    Button(onClick = {
                        scope.launch { store.save(current()) }
                        onConnect()
                    }) { Text("اتصال") }
                }
            }
        }
    }
}
