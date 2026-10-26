package com.klink.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class Stage { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

data class TunnelStatus(val stage: Stage = Stage.DISCONNECTED, val message: String = "")

/** Process-wide VPN status: written by the service, observed by the UI. */
object TunnelState {
    private val _status = MutableStateFlow(TunnelStatus())
    val status: StateFlow<TunnelStatus> = _status.asStateFlow()

    fun set(stage: Stage, message: String = "") {
        _status.value = TunnelStatus(stage, message)
    }
}
