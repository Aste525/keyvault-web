package com.keyvault.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

class KeyVaultVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var running = false
    private val CHANNEL = "kv_vpn"
    private var thread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(2, buildNotif())
        startVpn()
        return START_STICKY
    }

    private fun buildNotif(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Key Vault VPN", NotificationManager.IMPORTANCE_LOW))
        val tier = Session.getTier(this)
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("Key Vault aktif — ${tier.name}")
            .setContentText("Trafik aplikasi pilihan sedang dienkripsi")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    private fun deriveKey(): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        d.update("keyvault-vpn-key".toByteArray())
        return d.digest()
    }

    private fun startVpn() {
        if (running) return
        val tier = Session.getTier(this)
        val builder = Builder()
            .setSession("Key Vault ${tier.name}")
            .addAddress("10.8.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0)
        val selected = SelectedApps.load(this)
        for (pkg in selected) try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
        tun = builder.establish()
        running = true
        val cipher = PacketCipher(deriveKey())
        thread = Thread { relay(cipher) }
        thread?.start()
    }

    private fun relay(cipher: PacketCipher) {
        val iface = tun ?: return
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val len = input.read(buf)
            if (len > 0) output.write(cipher.encrypt(buf.copyOf(len)))
        }
    }

    override fun onDestroy() {
        running = false
        thread?.interrupt()
        tun?.close()
        super.onDestroy()
    }
}
