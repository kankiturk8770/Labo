package com.edge.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private lateinit var store: SettingsStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = SettingsStore(applicationContext)
        setContent { EdgeTheme { AppScreen(store, ::launchVpn, ::stopVpn) } }
    }

    private fun launchVpn() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            vpnPermission.launch(prepare)
        } else {
            startService(Intent(this, EdgeVpnService::class.java))
        }
    }

    private fun stopVpn() {
        startService(Intent(this, EdgeVpnService::class.java).setAction(EdgeVpnService.ACTION_STOP))
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startService(Intent(this, EdgeVpnService::class.java))
            } else {
                TunnelState.set(Stage.ERROR, "VPN permission denied")
            }
        }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppScreen(
    store: SettingsStore,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val status by TunnelState.status.collectAsState()

    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("8443") }
    var path by remember { mutableStateOf("/tunnel") }
    var secret by remember { mutableStateOf("") }
    var sni by remember { mutableStateOf("") }
    var insecure by remember { mutableStateOf(false) }
    var probe by remember { mutableStateOf<String?>(null) }
    var loaded by remember { mutableStateOf(false) }

    if (!loaded) {
        scope.launch {
            val c = store.config.first()
            host = c.host; port = c.port.toString(); path = c.tunnelPath
            secret = c.secret; sni = if (c.sni == c.host) "" else c.sni
            insecure = c.allowInsecureTls; loaded = true
        }
    }

    fun current() = EdgeConfig(
        host = host.trim(),
        port = port.toIntOrNull() ?: 0,
        tunnelPath = path.trim().ifBlank { "/tunnel" },
        secret = secret,
        sni = sni.trim().ifBlank { host.trim() },
        allowInsecureTls = insecure,
    )

    Scaffold(topBar = { TopAppBar(title = { Text("Edge VPN") }) }) { pad ->
        Column(
            Modifier
                .padding(pad)
                .padding(16.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(status)

            OutlinedTextField(host, { host = it }, label = { Text("Gateway host") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(port, { port = it.filter(Char::isDigit) }, label = { Text("Port") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(path, { path = it }, label = { Text("Tunnel path") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(secret, { secret = it }, label = { Text("HMAC secret (>= 32 bytes)") },
                singleLine = true, visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth())
            OutlinedTextField(sni, { sni = it }, label = { Text("SNI / Host (optional, for fronting)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(insecure, { insecure = it })
                Spacer(Modifier.height(0.dp))
                Text("  Allow insecure TLS (local testing only)")
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = {
                    scope.launch {
                        store.save(current())
                        probe = "Testing…"
                        val r = withContext(Dispatchers.IO) {
                            val cfg = current()
                            cfg.validate()?.let { return@withContext ProbeResult(false, it) }
                            GatewayProbe(cfg).run()
                        }
                        probe = (if (r.ok) "✓ " else "✗ ") + r.detail
                    }
                }) { Text("Test") }

                val connected = status.stage == Stage.CONNECTED ||
                    status.stage == Stage.CONNECTING || status.stage == Stage.RECONNECTING
                if (connected) {
                    Button(onClick = onDisconnect) { Text("Disconnect") }
                } else {
                    Button(onClick = {
                        scope.launch { store.save(current()) }
                        onConnect()
                    }) { Text("Connect") }
                }
            }

            probe?.let {
                Text(it, style = MaterialTheme.typography.bodySmall)
            }

            Text(
                "Routing and the HMAC signing contract live on the gateway; this client only " +
                    "signs the exact bytes the gateway validates and tunnels raw IP packets over " +
                    "the authenticated websocket.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun StatusCard(status: TunnelStatus) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (status.stage == Stage.CONNECTING || status.stage == Stage.RECONNECTING) {
                    CircularProgressIndicator(Modifier.height(18.dp).padding(end = 10.dp))
                }
                Text(status.stage.name, style = MaterialTheme.typography.titleMedium)
            }
            if (status.message.isNotBlank()) {
                Text(status.message, style = MaterialTheme.typography.bodyMedium)
            }
            if (status.stage == Stage.CONNECTED) {
                Text(
                    "↑ ${human(status.bytesUp)}   ↓ ${human(status.bytesDown)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

private fun human(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    return String.format("%.2f GB", mb / 1024.0)
}
