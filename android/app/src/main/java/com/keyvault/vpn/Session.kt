package com.keyvault.vpn

enum class Tier { GENKAI, CYBORG, CYPHERSTAR }

object Session {
    private const val PREFS = "kv_session"

    fun getTier(ctx: android.content.Context): Tier {
        val p = ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        return when (p.getString("tier", "GENKAI")) {
            "CYBORG" -> Tier.CYBORG
            "CYPHERSTAR" -> Tier.CYPHERSTAR
            else -> Tier.GENKAI
        }
    }

    fun verifyAndUpgrade(ctx: android.content.Context, txid: String, tier: Tier) {
        val p = ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        p.edit().putString("tier", tier.name).putString("txid", txid).apply()
    }
}
