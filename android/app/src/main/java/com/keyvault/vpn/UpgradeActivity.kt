package com.keyvault.vpn

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import java.net.URL

class UpgradeActivity : AppCompatActivity() {
    private val BTC_CYBORG = "19EeAmjHcBrddqwBQ8AKNsYWy84eXViAP3"
    private val BTC_CYPHERSTAR = "12EDhTKuQY5yarNA3SJHtL9NmRiAEMZwA3"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 48, 48, 48) }
        root.addView(TextView(this).apply { text = "Upgrade Key Vault"; textSize = 22f })
        root.addView(TextView(this).apply {
            text = "CYBORG (~Rp20.000):\n$BTC_CYBORG\n\nCYPHERSTAR (~Rp50.000):\n$BTC_CYPHERSTAR\n\nHarga Bitcoin mengikuti CoinGecko secara otomatis.\nFee ditanggung sendiri. Kirim TXID setelah bayar."
            textSize = 13f; setPadding(0, 16, 0, 16)
        })
        val txInput = EditText(this).apply { hint = "Tempel TXID di sini (64 karakter)" }
        root.addView(txInput)
        root.addView(Button(this).apply {
            text = "Verifikasi & Aktifkan Cyborg"
            setOnClickListener { verify(txInput.text.toString().trim(), Tier.CYBORG) }
        })
        root.addView(Button(this).apply {
            text = "Verifikasi & Aktifkan Cypherstar"
            setOnClickListener { verify(txInput.text.toString().trim(), Tier.CYPHERSTAR) }
        })
        setContentView(root)
    }

    private fun getMinSat(tier: Tier): Long {
        return try {
            val json = JSONObject(URL("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=idr").readText())
            val btcIdr = json.getJSONObject("bitcoin").getDouble("idr")
            val idr = if (tier == Tier.CYBORG) 20000.0 else 50000.0
            ((idr / btcIdr) * 100_000_000).toLong()
        } catch (_: Exception) { if (tier == Tier.CYBORG) 30000L else 75000L }
    }

    private fun verify(txid: String, tier: Tier) {
        if (txid.length != 64) { Toast.makeText(this, "TXID harus 64 karakter", Toast.LENGTH_SHORT).show(); return }
        val addr = if (tier == Tier.CYBORG) BTC_CYBORG else BTC_CYPHERSTAR
        Toast.makeText(this, "Memverifikasi...", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                val minSat = getMinSat(tier)
                val vout = JSONObject(URL("https://mempool.space/api/tx/$txid").readText()).getJSONArray("vout")
                var found = false
                for (i in 0 until vout.length()) {
                    val o = vout.getJSONObject(i)
                    if (o.optString("scriptpubkey_address") == addr && o.getLong("value") >= minSat) { found = true; break }
                }
                runOnUiThread {
                    if (found) { Session.verifyAndUpgrade(this, txid, tier); Toast.makeText(this, "${tier.name} aktif! Restart app.", Toast.LENGTH_LONG).show(); finish() }
                    else Toast.makeText(this, "Tidak ditemukan ke $addr min $minSat sat", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) { runOnUiThread { Toast.makeText(this, "Gagal: ${e.message}", Toast.LENGTH_LONG).show() } }
        }.start()
    }
}
