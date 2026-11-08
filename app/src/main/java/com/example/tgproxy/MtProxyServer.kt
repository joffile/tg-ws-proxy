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
import java.net.SocketException
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

// Путь A (WebSocket): адреса серверов Telegram по номеру датацентра
private val WS_IPS = mapOf(
    1 to listOf("149.154.175.50", "149.154.175.205", "149.154.174.100"),
    2 to listOf("149.154.167.220", "149.154.167.51"),
    3 to listOf("149.154.175.100", "149.154.174.100"),
    4 to listOf("149.154.167.220", "149.154.167.91"),
    5 to listOf("149.154.171.5", "91.108.56.130", "149.154.170.100")
)

// Путь B (прямой TCP на сервер датацентра): адреса из default_dc_ips
private val TCP_IPS = mapOf(
    1 to "149.154.175.50",
    2 to "149.154.167.51",
    3 to "149.154.175.100",
    4 to "149.154.167.91",
    5 to "149.154.171.5",
    203 to "91.105.192.100"
)

// Путь C (WebSocket через Cloudflare): список доменов с GitHub, зашифрован шифром Цезаря
private const val CF_LIST_URL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt"
private val CF_FALLBACK = listOf("virkgj.com", "vmmzovy.com", "mkuosckvso.com")

// Сдвиг букв назад на количество букв в имени, суффикс .com заменяется на .co.uk
private fun decodeDomain(enc: String): String? {
    if (!enc.endsWith(".com")) return null
    val prefix = enc.removeSuffix(".com")
    val n = prefix.count { it in 'a'..'z' || it in 'A'..'Z' }
    val decoded = prefix.map { c ->
        when (c) {
            in 'a'..'z' -> 'a' + ((c - 'a') - n).mod(26)
            in 'A'..'Z' -> 'A' + ((c - 'A') - n).mod(26)
            else -> c
        }
    }.joinToString("")
    return decoded + ".co.uk"
}

private object CfDomains {
    @Volatile var list: List<String> = emptyList<String>()

    fun load(base: OkHttpClient) {
        if (list.isNotEmpty()) return
        val body = try {
            base.newBuilder().callTimeout(10, TimeUnit.SECONDS).build()
                .newCall(Request.Builder().url(CF_LIST_URL).build())
                .execute().use { it.body?.string() }
        } catch (e: Exception) {
            null
        }
        val fromNet = (body ?: "").lines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { decodeDomain(it) }
        list = if (fromNet.isNotEmpty()) fromNet else CF_FALLBACK.mapNotNull { decodeDomain(it) }
    }
}

// Имя kwsN.web.telegram.org превращаем в IP сервера. Остальные имена (Cloudflare) не трогаем.
private val telegramDns = object : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val dc = if (hostname.endsWith(".web.telegram.org"))
            Regex("^kws(\\d+)").find(hostname)?.groupValues?.get(1)?.toIntOrNull() else null
        val ips = dc?.let { WS_IPS[it] }
        return if (ips != null) ips.map { InetAddress.getByName(it) } else Dns.SYSTEM.lookup(hostname)
    }
}

/**
 * Локальный прокси для Telegram (MTProto obfuscated2).
 * Пути по порядку: A (WebSocket), B (прямой TCP), C (WebSocket через Cloudflare).
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
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .pingInterval(20, TimeUnit.SECONDS)
        .build()
    private var server: ServerSocket? = null

    // true: путь A в прошлый раз сразу оборвался, в этот раз сначала пробуем путь B
    @Volatile private var tcpFirst = false

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
        var tcp: Socket? = null
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()

            // 1. Рукопожатие клиента: ключ, IV, тип протокола и номер DC
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

            // 3. Ответы клиенту шифруем ключами из его рукопожатия
            val rev = hs.reversedArray()
            val cliEnc = aes(mtKey(rev.copyOfRange(8, 40)), rev.copyOfRange(40, 56))

            // 4. Путь A: WebSocket к серверам Telegram
            if (!tcpFirst) {
                log("Путь A: WebSocket к DC $wsDc...")
                val names = if (media) listOf("kws$wsDc-1", "kws$wsDc") else listOf("kws$wsDc", "kws$wsDc-1")
                val link = openWs(names.map { "$it.web.telegram.org" }, client, cliEnc, tgDec)
                if (link != null) {
                    ws = link.ws
                    serve(link, handshake, input, clientDec, tgEnc)
                    return
                }
                log("Путь A не работает, пробую путь B")
            }

            // 5. Путь B: прямое TCP-соединение с сервером DC
            log("Путь B: прямое соединение с DC $dc...")
            val remote = connectTcp(dc)
            if (remote != null) {
                tcp = remote
                remote.getOutputStream().apply { write(handshake); flush() }
                log("Путь B: соединение установлено")
                tcpFirst = false
                startTcpReader(remote, client, tgDec, cliEnc)
                pump(input, clientDec, tgEnc) { remote.getOutputStream().apply { write(it); flush() } }
                return
            }
            log("Путь B не работает, пробую путь C")

            // 6. Путь C: WebSocket через Cloudflare, перебор доменов из списка
            CfDomains.load(http)
            for (domain in CfDomains.list) {
                if (client.isClosed) return
                log("Путь C: Cloudflare, $domain...")
                val link = openWs(listOf("kws$dc.$domain"), client, cliEnc, tgDec) ?: continue
                ws = link.ws
                serve(link, handshake, input, clientDec, tgEnc)
                return
            }
            log("Все пути закрыты: A, B и C не работают")
            tcpFirst = false
        } catch (e: EOFException) {
            // клиент закрыл соединение
        } catch (e: SocketException) {
            // связь закрыта, причина уже в статусе
        } catch (e: Exception) {
            log("Ошибка: ${e.message}")
        } finally {
            ws?.close(1000, null)
            tcp?.let { runCatching { it.close() } }
            runCatching { client.close() }
            sockets.remove(client)
        }
    }

    // Отправляет рукопожатие и перекачивает данные через открытый WebSocket
    private fun serve(link: Link, handshake: ByteArray, input: InputStream, clientDec: Cipher, tgEnc: Cipher) {
        link.ws.send(handshake.toByteString())
        log("WebSocket открыт, жду ответ Telegram")
        try {
            pump(input, clientDec, tgEnc) { link.ws.send(it.toByteString()) }
        } finally {
            tcpFirst = !link.up.gotData
        }
    }

    // Клиент -> Telegram: расшифровываем, шифруем для Telegram и отправляем
    private fun pump(input: InputStream, clientDec: Cipher, tgEnc: Cipher, send: (ByteArray) -> Unit) {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            val chunk = clientDec.update(buf.copyOf(n)) ?: continue
            send(tgEnc.update(chunk) ?: continue)
        }
    }

    // Telegram -> клиент по прямому TCP-соединению
    private fun startTcpReader(remote: Socket, client: Socket, tgDec: Cipher, cliEnc: Cipher) {
        pool.execute {
            try {
                val tin = remote.getInputStream()
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = tin.read(buf)
                    if (n < 0) break
                    val dec = tgDec.update(buf.copyOf(n)) ?: continue
                    val out = cliEnc.update(dec) ?: continue
                    client.getOutputStream().apply { write(out); flush() }
                }
            } catch (e: Exception) {
                // соединение закрыто
            } finally {
                runCatching { client.close() }
            }
        }
    }

    private fun connectTcp(dc: Int): Socket? {
        val ip = TCP_IPS[dc] ?: return null
        return try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(ip, 443), 5000)
            }
        } catch (e: Exception) {
            log("Путь B: сервер $ip не отвечает")
            null
        }
    }

    // Пробует адреса по очереди. Для каждого адреса свой Upstream, иначе ожидание сломается
    private fun openWs(hosts: List<String>, client: Socket, cliEnc: Cipher, tgDec: Cipher): Link? {
        for (host in hosts) {
            val up = Upstream(client, cliEnc, tgDec)
            val req = Request.Builder()
                .url("https://$host/apiws")
                .header("Sec-WebSocket-Protocol", "binary")
                .header("Origin", "https://web.telegram.org")
                .header("User-Agent", UA)
                .build()
            val ws = http.newWebSocket(req, up)
            up.opened.await(10, TimeUnit.SECONDS)
            if (up.isOpen) return Link(ws, up)
            ws.cancel()
        }
        return null
    }

    private inner class Link(val ws: WebSocket, val up: Upstream)

    private inner class Upstream(
        private val client: Socket,
        private val cliEnc: Cipher,
        private val tgDec: Cipher
    ) : WebSocketListener() {
        val opened = CountDownLatch(1)
        @Volatile var isOpen = false
        @Volatile var gotData = false

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
            val why = t.message ?: t.javaClass.simpleName
            if (isOpen) {
                log("Сервер оборвал связь: $why")
                runCatching { client.close() }
            } else {
                log("Нет связи с сервером: $why")
            }
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            if (isOpen) {
                log("Сервер закрыл связь: код $code, $reason")
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
