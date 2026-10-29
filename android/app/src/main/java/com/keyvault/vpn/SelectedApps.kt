package com.keyvault.vpn

import android.content.Context
import android.content.pm.PackageManager

object SelectedApps {
    private const val PREFS = "kv_apps"

    data class AppInfo(val packageName: String, val label: String)

    fun listInstalled(ctx: Context): List<AppInfo> {
        val pm = ctx.packageManager
        return pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { pm.getLaunchIntentForPackage(it.packageName) != null }
            .map { AppInfo(it.packageName, pm.getApplicationLabel(it).toString()) }
            .sortedBy { it.label.lowercase() }
    }

    fun load(ctx: Context): Set<String> =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet("pkgs", emptySet()) ?: emptySet()

    fun save(ctx: Context, pkgs: Set<String>) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet("pkgs", pkgs).apply()
}
