package com.keyvault.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest

class KeyVaultVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var running = false
    private val CHANNEL = "kv_vpn"
    private val TAG = "KeyVaultVPN"
    private var thread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            startForeground(2, buildNotif())
            startVpn()
        } catch (e: Exception) {
            Log.e(TAG, "crash: ${e.stackTraceToString()}")
            stopSelf()
        }
        return START_STICKY
    }

    private fun buildNotif(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Key Vault VPN", NotificationManager.IMPORTANCE_LOW))
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("Key Vault NOS VPN — ${Session.getTier(this).name}")
            .setContentText("Trafik aplikasi pilihan sedang dienkripsi (Serpent-256)")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true).build()
    }

    private fun deriveKey(): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        d.update("keyvault-nos-vpn-key-v1".toByteArray())
        d.update(android.os.Build.FINGERPRINT.toByteArray())
        return d.digest()
    }

    private fun startVpn() {
        if (running) return
        try {
            val builder = Builder()
                .setSession("Key Vault NOS VPN")
                .addAddress("10.99.0.1", 32)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .setMtu(1400)
                .setBlocking(true)
            val selected = SelectedApps.load(this)
            if (selected.isNotEmpty()) for (pkg in selected) try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
            tun = builder.establish() ?: throw IllegalStateException("establish() null — izin VPN belum diberikan")
            running = true
            val cipher = PacketCipher(deriveKey())
            thread = Thread({ relay(cipher) }, "kv-relay").also { it.isDaemon = true; it.start() }
        } catch (e: Exception) {
            Log.e(TAG, "startVpn gagal: ${e.stackTraceToString()}")
            running = false; tun?.close(); stopSelf()
        }
    }

    private fun relay(cipher: PacketCipher) {
        val input = FileInputStream(tun!!.fileDescriptor)
        val output = FileOutputStream(tun!!.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            try { val len = input.read(buf); if (len > 0) output.write(cipher.encrypt(buf.copyOf(len))) }
            catch (e: Exception) { if (running) Log.e(TAG, "relay: ${e.message}"); break }
        }
    }

    override fun onDestroy() {
        running = false; thread?.interrupt()
        try { tun?.close() } catch (_: Exception) {}
        tun = null; super.onDestroy()
    }
}
