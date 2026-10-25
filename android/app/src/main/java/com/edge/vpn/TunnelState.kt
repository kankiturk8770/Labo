package com.edge.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class Stage { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, ERROR }

data class TunnelStatus(
    val stage: Stage = Stage.DISCONNECTED,
    val message: String = "",
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
)

/** Process-wide VPN status, observed by the UI and written by the service. */
object TunnelState {
    private val _status = MutableStateFlow(TunnelStatus())
    val status: StateFlow<TunnelStatus> = _status.asStateFlow()

    fun update(transform: (TunnelStatus) -> TunnelStatus) {
        _status.value = transform(_status.value)
    }

    fun set(stage: Stage, message: String = "") {
        _status.value = _status.value.copy(stage = stage, message = message)
    }

    fun traffic(up: Long, down: Long) {
        _status.value = _status.value.copy(bytesUp = up, bytesDown = down)
    }
}
