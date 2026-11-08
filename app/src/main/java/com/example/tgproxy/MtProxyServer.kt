package com.example.tgproxy

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.MutableStateFlow
import java.security.SecureRandom

object ProxyState {
    val running = MutableStateFlow(false)
    val message = MutableStateFlow("Остановлен")
}

class ProxyService : Service() {
    private var server: MtProxyServer? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopProxy()
            stopSelf()
            return START_NOT_STICKY
        }
        val channel = NotificationChannel(CHANNEL_ID, "Прокси", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TG WS Proxy работает")
            .setContentText("Прокси для Telegram: 127.0.0.1:$PORT")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            .addAction(0, "Стоп", PendingIntent.getService(this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE))
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, notification)
        }
        if (server == null) startProxy()
        // START_STICKY: если система убьёт службу, она запустится снова сама
        return START_STICKY
    }

    private fun startProxy() {
        acquireLocks()
        val srv = MtProxyServer(PORT, hexToBytes(secretHex(this))) { ProxyState.message.value = it }
        try {
            srv.start()
            server = srv
            ProxyState.running.value = true
            ProxyState.message.value = "Слушает 127.0.0.1:$PORT"
        } catch (e: Exception) {
            ProxyState.message.value = "Порт $PORT недоступен: ${e.message}"
            releaseLocks()
            stopSelf()
        }
    }

    // Не даём процессору и Wi-Fi уснуть, пока работает прокси
    private fun acquireLocks() {
        if (wakeLock == null) {
            wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TgWsProxy:cpu")
                .apply { setReferenceCounted(false); acquire() }
        }
        if (wifiLock == null) {
            wifiLock = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
                .createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "TgWsProxy:wifi")
                .apply { setReferenceCounted(false); acquire() }
        }
    }

    private fun releaseLocks() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wifiLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        wifiLock = null
    }

    private fun stopProxy() {
        server?.stop()
        server = null
        releaseLocks()
        ProxyState.running.value = false
        ProxyState.message.value = "Остановлен"
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.example.tgproxy.STOP"
        const val PORT = 1443
        private const val CHANNEL_ID = "proxy"
        private const val NOTIF_ID = 1

        fun secretHex(ctx: Context): String {
            val prefs = ctx.getSharedPreferences("tgproxy", Context.MODE_PRIVATE)
            return prefs.getString("secret", null) ?: ByteArray(16).also { SecureRandom().nextBytes(it) }
                .joinToString("") { "%02x".format(it) }
                .also { prefs.edit().putString("secret", it).apply() }
        }

        fun proxyLink(ctx: Context) = "tg://proxy?server=127.0.0.1&port=$PORT&secret=" + secretHex(ctx)

        fun hexToBytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
