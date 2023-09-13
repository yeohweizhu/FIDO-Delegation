package anon.fido.delegation

import org.bouncycastle.asn1.*

class ASN1ECDSA(private val r: ASN1Integer, private val s: ASN1Integer) : ASN1Encodable {

    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector()
        v.add(r)
        v.add(s)
        return DERSequence(v)
    }
}