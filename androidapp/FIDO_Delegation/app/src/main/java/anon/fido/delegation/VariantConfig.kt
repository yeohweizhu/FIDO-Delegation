package anon.fido.delegation

class VariantConfig(val count:Int, val vari:Variant) {

    companion object {
        fun BasicInstance(): VariantConfig {
            return VariantConfig(256, Variant.BASIC)
        }

        fun ByteInstance(): VariantConfig {
            return VariantConfig(32, Variant.BYTE)
        }
    }
}

enum class Variant {
    BASIC, BYTE
}