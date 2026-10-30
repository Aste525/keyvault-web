package com.keyvault.vpn

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationChannel
import android.app.NotificationManager
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import androidx.core.app.NotificationCompat

class KeyVaultAccessibility : AccessibilityService() {
    private val CHANNEL = "kv_monitor"
    private val TAG = "KeyVaultMonitor"
    private var lastPkg = ""
    private var notifId = 1000

    override fun onServiceConnected() {
        try {
            val info = AccessibilityServiceInfo()
            info.eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            info.notificationTimeout = 200
            serviceInfo = info
        } catch (e: Exception) { Log.e(TAG, "onServiceConnected: ${e.message}") }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        try {
            if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
            val pkg = event.packageName?.toString() ?: return
            if (pkg == lastPkg || pkg == packageName) return
            lastPkg = pkg
            if (pkg !in SelectedApps.load(this)) return
            val pm = packageManager
            val label = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg }
            val installer = try { pm.getInstallSourceInfo(pkg).installingPackageName ?: "Sumber tidak diketahui" } catch (_: Exception) { "Tidak diketahui" }
            val isPlay = installer == "com.android.vending"
            showNotif(if (isPlay) "✓ $label" else "⚠️ $label", if (isPlay) "Resmi dari Google Play Store" else "BUKAN Play Store — dari: $installer", !isPlay)
        } catch (e: Exception) { Log.e(TAG, "event error: ${e.message}") }
    }

    private fun showNotif(title: String, msg: String, warn: Boolean) {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Key Vault Monitor", NotificationManager.IMPORTANCE_HIGH))
            nm.notify(notifId++, NotificationCompat.Builder(this, CHANNEL)
                .setContentTitle(title).setContentText(msg)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(if (warn) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true).build())
        } catch (e: Exception) { Log.e(TAG, "notif: ${e.message}") }
    }

    override fun onInterrupt() {}
}
