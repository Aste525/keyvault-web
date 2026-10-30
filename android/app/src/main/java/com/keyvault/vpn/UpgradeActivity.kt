package com.keyvault.vpn

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import java.net.URL

class UpgradeActivity : AppCompatActivity() {
    private val BTC_ADDR = "12EDhTKuQY5yarNA3SJHtL9NmRiAEMZwA3"
    private val CYBORG_SAT = 30000L
    private val CYPHERSTAR_SAT = 75000L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        root.addView(TextView(this).apply { text = "Upgrade Key Vault"; textSize = 22f })
        root.addView(TextView(this).apply {
            text = "Kirim Bitcoin ke alamat ini:\n$BTC_ADDR\n\nCyborg: ~Rp20.000 ($CYBORG_SAT sat)\nCypherstar: ~Rp50.000 ($CYPHERSTAR_SAT sat)\n\nFee Bitcoin ditanggung sendiri."
            textSize = 14f; setPadding(0, 16, 0, 16)
        })
        val txInput = EditText(this).apply { hint = "Masukkan TXID setelah bayar" }
        root.addView(txInput)
        root.addView(Button(this).apply {
            text = "Verifikasi & Aktifkan Cyborg"
            setOnClickListener { verify(txInput.text.toString().trim(), Tier.CYBORG, CYBORG_SAT) }
        })
        root.addView(Button(this).apply {
            text = "Verifikasi & Aktifkan Cypherstar"
            setOnClickListener { verify(txInput.text.toString().trim(), Tier.CYPHERSTAR, CYPHERSTAR_SAT) }
        })
        val status = TextView(this).apply { setPadding(0, 16, 0, 0) }
        root.addView(status)
        setContentView(root)
    }

    private fun verify(txid: String, tier: Tier, minSat: Long) {
        if (txid.length != 64) { Toast.makeText(this, "TXID tidak valid", Toast.LENGTH_SHORT).show(); return }
        Toast.makeText(this, "Memverifikasi...", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val url = "https://mempool.space/api/tx/$txid"
                val json = JSONObject(URL(url).readText())
                val vout = json.getJSONArray("vout")
                var found = false
                var amount = 0L
                for (i in 0 until vout.length()) {
                    val out = vout.getJSONObject(i)
                    if (out.optString("scriptpubkey_address") == BTC_ADDR) {
                        amount = out.getLong("value")
                        if (amount >= minSat) { found = true; break }
                    }
                }
                runOnUiThread {
                    if (found) {
                        Session.verifyAndUpgrade(this, txid, tier)
                        Toast.makeText(this, "${tier.name} aktif! Restart app.", Toast.LENGTH_LONG).show()
                        finish()
                    } else {
                        Toast.makeText(this, "Pembayaran tidak ditemukan atau kurang (min $minSat sat ke $BTC_ADDR)", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "Gagal verifikasi: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }
}
