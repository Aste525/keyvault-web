package com.keyvault.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val REQUEST_VPN = 1
    private lateinit var appList: ListView
    private lateinit var installed: List<SelectedApps.AppInfo>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        val tier = Session.getTier(this)
        root.addView(TextView(this).apply {
            text = "Key Vault — ${tier.name}"
            textSize = 22f
        })
        root.addView(TextView(this).apply {
            text = when (tier) {
                Tier.GENKAI -> "Gratis — enkripsi acak, regional, maks 30 user/DNS, 1 jam"
                Tier.CYBORG -> "Cyborg — RIPEMD-320 + enkripsi acak, DNS terbaik"
                Tier.CYPHERSTAR -> "Cypherstar — Mixnet penuh, semua kombinasi bebas"
            }
            textSize = 14f; setPadding(0, 8, 0, 16)
        })
        if (tier == Tier.GENKAI) {
            root.addView(Button(this).apply {
                text = "⬆ Upgrade ke Cyborg (Rp20rb) atau Cypherstar (Rp50rb)"
                setOnClickListener {
                    startActivity(Intent(this@MainActivity, UpgradeActivity::class.java))
                }
            })
        }
        installed = SelectedApps.listInstalled(this)
        val selected = SelectedApps.load(this).toMutableSet()
        val labels = installed.map { it.label }
        val checked = BooleanArray(installed.size) { installed[it].packageName in selected }
        appList = ListView(this)
        appList.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_multiple_choice, labels)
        appList.choiceMode = ListView.CHOICE_MODE_MULTIPLE
        for (i in checked.indices) if (checked[i]) appList.setItemChecked(i, true)
        appList.layoutParams = LinearLayout.LayoutParams(-1, 0, 1f)
        root.addView(appList)
        root.addView(Button(this).apply {
            text = "Aktifkan VPN + Monitor"
            setOnClickListener {
                val sel = mutableSetOf<String>()
                for (i in 0 until appList.count) if (appList.isItemChecked(i)) sel.add(installed[i].packageName)
                SelectedApps.save(this@MainActivity, sel)
                try {
                    val intent = VpnService.prepare(this@MainActivity)
                    if (intent != null) startActivityForResult(intent, REQUEST_VPN) else startVpn()
                } catch (e: Exception) {
                    Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        })
        root.addView(Button(this).apply {
            text = "Matikan VPN"
            setOnClickListener {
                stopService(Intent(this@MainActivity, KeyVaultVpnService::class.java))
                Toast.makeText(this@MainActivity, "VPN dimatikan", Toast.LENGTH_SHORT).show()
            }
        })
        root.addView(Button(this).apply {
            text = "Aktifkan Monitor Aplikasi"
            setOnClickListener { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        })
        setContentView(root)
    }

    private fun startVpn() {
        try {
            startForegroundService(Intent(this, KeyVaultVpnService::class.java))
            Toast.makeText(this, "VPN aktif", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Gagal: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) startVpn()
        super.onActivityResult(requestCode, resultCode, data)
    }
}
