package com.keyvault.vpn

import android.accessibilityservice.AccessibilityService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityEvent
import androidx.core.app.NotificationCompat

class KeyVaultAccessibility : AccessibilityService() {
    private val CHANNEL = "kv_monitor"
    private var lastPkg = ""

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val pkg = event?.packageName?.toString() ?: return
        if (pkg == lastPkg || pkg == packageName) return
        lastPkg = pkg
        val selected = SelectedApps.load(this)
        if (pkg !in selected) return
        val pm = packageManager
        val label = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg }
        val installer = try { pm.getInstallSourceInfo(pkg).installingPackageName ?: "Tidak diketahui" } catch (_: Exception) { "Tidak diketahui" }
        val isPlay = installer == "com.android.vending"
        val msg = if (isPlay) "$label: dari Google Play Store" else "$label: BUKAN dari Play Store — dari $installer"
        showNotif(label, msg, !isPlay)
    }

    private fun showNotif(title: String, msg: String, warn: Boolean) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Key Vault Monitor", NotificationManager.IMPORTANCE_HIGH))
        val n = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(if (warn) "⚠️ $title" else "✓ $title")
            .setContentText(msg)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        nm.notify(System.currentTimeMillis().toInt(), n)
    }

    override fun onInterrupt() {}
}
