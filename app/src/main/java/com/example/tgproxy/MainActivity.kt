package com.example.tgproxy

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat

object BatteryState {
    var ignoring by mutableStateOf(false)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ProxyScreen()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        BatteryState.ignoring = getSystemService(PowerManager::class.java)
            .isIgnoringBatteryOptimizations(packageName)
    }
}

@Composable
fun ProxyScreen() {
    val context = LocalContext.current
    val running by ProxyState.running.collectAsState()
    val message by ProxyState.message.collectAsState()
    val ignoring = BatteryState.ignoring
    val link = ProxyService.proxyLink(context)
    val askNotif = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    val buttonModifier = Modifier.fillMaxWidth(0.8f).widthIn(max = 360.dp)

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(if (running) "Работает" else "Остановлен", style = MaterialTheme.typography.headlineMedium)
        Text(message, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))

        Button(
            onClick = {
                val intent = Intent(context, ProxyService::class.java)
                if (running) {
                    context.startService(intent.setAction(ProxyService.ACTION_STOP))
                } else {
                    if (Build.VERSION.SDK_INT >= 33) askNotif.launch(Manifest.permission.POST_NOTIFICATIONS)
                    ContextCompat.startForegroundService(context, intent)
                }
            },
            modifier = buttonModifier.padding(top = 32.dp)
        ) { Text(if (running) "Стоп" else "Старт") }

        OutlinedButton(
            onClick = {
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)))
                } catch (e: ActivityNotFoundException) {
                    Toast.makeText(context, "Telegram не найден", Toast.LENGTH_SHORT).show()
                }
            },
            modifier = buttonModifier.padding(top = 16.dp)
        ) { Text("Подключить в Telegram") }

        OutlinedButton(
            onClick = {
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("proxy", link))
                Toast.makeText(context, "Ссылка скопирована", Toast.LENGTH_SHORT).show()
            },
            modifier = buttonModifier.padding(top = 12.dp)
        ) { Text("Скопировать ссылку") }

        OutlinedButton(
            onClick = {
                if (!ignoring) {
                    try {
                        context.startActivity(
                            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                Uri.parse("package:" + context.packageName))
                        )
                    } catch (e: ActivityNotFoundException) {
                        Toast.makeText(context, "Откройте настройки батареи вручную", Toast.LENGTH_LONG).show()
                    }
                }
            },
            modifier = buttonModifier.padding(top = 12.dp)
        ) { Text(if (ignoring) "Работа в фоне разрешена" else "Разрешить работу в фоне") }
    }
}
