package com.example.tgproxy

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.EOFException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val TAG_ABRIDGED = ByteArray(4) { 0xEF.toByte() }
private val TAG_INTERMEDIATE = ByteArray(4) { 0xEE.toByte() }
private val TAG_PADDED = ByteArray(4) { 0xDD.toByte() }
private const val UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// Адреса серверов Telegram по номеру DC, как в tg-ws-proxy-rs.
// Подключаемся по IP, а не по имени: так обходятся DNS-блокировки.
private val DC_IPS = mapOf(
    1 to "149.154.175.50",
    2 to "149.154.167.220",
    3 to "149.154.175.100",
    4 to "149.154.167.220",
    5 to "149.154.171.5"
)

// Имя kws2.web.telegram.org превращаем в IP сервера DC 2, TLS-имя остаётся прежним
private val telegramDns = object : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val dc = Regex("kws(\\d+)").find(hostname)?.groupValues?.get(1)?.toIntOrNull()
        val ip = dc?.let { DC_IPS[it] }
        return if (ip != null) listOf(InetAddress.getByName(ip)) else Dns.SYSTEM.lookup(hostname)
    }
}

/**
 * Локальный прокси для Telegram (протокол MTProto obfuscated2).
 * Принимает Telegram на 127.0.0.1 и пересылает трафик через WebSocket
 * на серверы Telegram (wss://kwsN.web.telegram.org/apiws).
 * Текущий этап работы пишется в статус приложения через log().
 */
class MtProxyServer(
    private val port: Int,
    private val secret: ByteArray,
    private val log: (String) -> Unit
) {
    private val pool = Executors.newCachedThreadPool()
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val rnd = SecureRandom()
    private val http = OkHttpClient.Builder()
        .dns(telegramDns)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .pingInterval(20, TimeUnit.SECONDS)
        .build()
    private var server: ServerSocket? = null

    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress("127.0.0.1", port))
        server = ss
        pool.execute {
            while (!ss.isClosed) {
                try {
                    val client = ss.accept()
                    sockets.add(client)
                    pool.execute { handle(client) }
                } catch (e: Exception) {
                    if (!ss.isClosed) log("Ошибка приёма: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        server?.close()
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
        pool.shutdownNow()
    }

    private fun handle(client: Socket) {
        var ws: WebSocket? = null
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()

            // 1. 64 байта рукопожатия клиента: ключ, IV, тип протокола и номер DC
            val hs = input.readExactly(64)
            val clientDec = aes(mtKey(hs.copyOfRange(8, 40)), hs.copyOfRange(40, 56))
            val plain = clientDec.update(hs)
            val tag = plain.copyOfRange(56, 60)
            if (!tag.contentEquals(TAG_ABRIDGED) && !tag.contentEquals(TAG_INTERMEDIATE) &&
                !tag.contentEquals(TAG_PADDED)) {
                log("Неверный секрет: удалите старый прокси в Telegram и подключите заново")
                return
            }
            val dcIdx = ((plain[60].toInt() and 0xff) or (plain[61].toInt() shl 8)).toShort().toInt()
            val media = dcIdx < 0
            val dc = Math.abs(dcIdx)
            val wsDc = if (dc == 203) 2 else dc
            if (wsDc !in 1..5) {
                log("Неизвестный номер DC: $dc")
                return
            }
            log("Telegram подключился, DC $dc")

            // 2. Своё рукопожатие к серверу Telegram (без секрета)
            val raw = randomInit(tag, dcIdx)
            val rawRev = raw.reversedArray()
            val tgEnc = aes(raw.copyOfRange(8, 40), raw.copyOfRange(40, 56))
            val keystream = tgEnc.update(ByteArray(64))
            val handshake = raw.copyOf()
            for (i in 56 until 64) handshake[i] = (raw[i].toInt() xor keystream[i].toInt()).toByte()
            val tgDec = aes(rawRev.copyOfRange(8, 40), rawRev.copyOfRange(40, 56))

            // 3. Ответы клиенту шифруем ключами из его рукопожатия, в обратном порядке
            val rev = hs.reversedArray()
            val cliEnc = aes(mtKey(rev.copyOfRange(8, 40)), rev.copyOfRange(40, 56))

            // 4. WebSocket к серверам Telegram и отправка своего рукопожатия
            val up = Upstream(client, cliEnc, tgDec)
            log("Подключаюсь к серверам Telegram, DC $wsDc...")
            val socket = connectWs(wsDc, media, up)
            if (socket == null) {
                log("Серверы Telegram недоступны (DC $dc)")
                return
            }
            ws = socket
            socket.send(handshake.toByteString())
            log("Связь с серверами установлена, жду ответ Telegram")

            // 5. Клиент -> Telegram
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                val chunk = clientDec.update(buf.copyOf(n)) ?: continue
                if (!socket.send(tgEnc.update(chunk).toByteString())) break
            }
        } catch (e: EOFException) {
            // клиент закрыл соединение
        } catch (e: java.net.SocketException) {
            // связь закрыта, причина уже записана в статус
        } catch (e: Exception) {
            log("Ошибка: ${e.message}")
        } finally {
            ws?.close(1000, null)
            runCatching { client.close() }
            sockets.remove(client)
        }
    }

    private fun connectWs(dc: Int, media: Boolean, up: Upstream): WebSocket? {
        val hosts = if (media) listOf("kws$dc-1", "kws$dc") else listOf("kws$dc", "kws$dc-1")
        for (host in hosts) {
            val req = Request.Builder()
                .url("https://$host.web.telegram.org/apiws")
                .header("Sec-WebSocket-Protocol", "binary")
                .header("Origin", "https://web.telegram.org")
                .header("User-Agent", UA)
                .build()
            val ws = http.newWebSocket(req, up)
            up.opened.await(10, TimeUnit.SECONDS)
            if (up.isOpen) return ws
            ws.cancel()
        }
        return null
    }

    private inner class Upstream(
        private val client: Socket,
        private val cliEnc: Cipher,
        private val tgDec: Cipher
    ) : WebSocketListener() {
        val opened = CountDownLatch(1)
        @Volatile var isOpen = false
        private var gotData = false

        override fun onOpen(webSocket: WebSocket, response: Response) {
            isOpen = true
            opened.countDown()
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            if (!gotData) {
                gotData = true
                log("Telegram отвечает, соединение рабочее")
            }
            try {
                val plain = tgDec.update(bytes.toByteArray()) ?: return
                val out = cliEnc.update(plain) ?: return
                client.getOutputStream().apply { write(out); flush() }
            } catch (e: Exception) {
                log("Ошибка данных: ${e.message}")
                webSocket.close(1000, null)
                runCatching { client.close() }
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            opened.countDown()
            if (isOpen) {
                log("Сервер Telegram оборвал связь: ${t.message}")
                runCatching { client.close() }
            } else {
                log("Нет связи с сервером Telegram: ${t.message}")
            }
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            if (isOpen) {
                log("Сервер Telegram закрыл связь: код $code, $reason")
                runCatching { client.close() }
            }
        }
    }

    private fun randomInit(tag: ByteArray, dcIdx: Int): ByteArray {
        while (true) {
            val b = ByteArray(64).also { rnd.nextBytes(it) }
            val first4 = b.copyOfRange(0, 4)
            val reserved = b[0] == 0xEF.toByte() ||
                first4.contentEquals(TAG_INTERMEDIATE) || first4.contentEquals(TAG_PADDED) ||
                String(first4, Charsets.ISO_8859_1) in setOf("POST", "GET ", "HEAD", "\u0016\u0003\u0001\u0002") ||
                b.copyOfRange(4, 8).all { it == 0.toByte() }
            if (reserved) continue
            tag.copyInto(b, 56)
            b[60] = (dcIdx and 0xff).toByte()
            b[61] = ((dcIdx shr 8) and 0xff).toByte()
            return b
        }
    }

    private fun aes(key: ByteArray, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/CTR/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        }

    private fun mtKey(seed: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(seed + secret)
}

private fun InputStream.readExactly(n: Int): ByteArray {
    val b = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = read(b, off, n - off)
        if (r < 0) throw EOFException("Соединение закрыто")
        off += r
    }
    return b
}
