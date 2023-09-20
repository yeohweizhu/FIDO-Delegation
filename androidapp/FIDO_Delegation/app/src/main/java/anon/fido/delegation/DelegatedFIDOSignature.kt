package anon.fido.delegation

import android.util.Log
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECCurve
import org.json.JSONObject
import java.math.BigInteger
import java.security.*
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.util.*
import javax.crypto.KeyAgreement
import kotlin.experimental.xor
import kotlin.math.pow

class DelegatedFIDOSignature(
    private var r: BigInteger,
    private var part1: BigInteger,
    private var vec1: String = "",
    private var vec0: String = "",
    private val allornot_1: String = "",
    private val allornot_0: String = "",
    private val serverepk: String = "",
    private val credential_id: String = "",
    private val user_handle: String = "",
    private val client_data: String = "",
    private val authenticator_data: String = "",
    private var keyalias: String,
    private val mainAct: MainActivity,
    private val varcon: VariantConfig
) {
    private val TAG = "DelegatedSignature"
    private val ecSpecSimple : ECParameterSpec
    private val ecSpec : ECNamedCurveParameterSpec
    private val allornot_1_bytearr_list: ArrayList<ByteArray> = ArrayList<ByteArray>()
    private val allornot_0_bytearr_list: ArrayList<ByteArray> = ArrayList<ByteArray>()
    private val vec1_bytearr_list: ArrayList<ByteArray> = ArrayList<ByteArray>()
    private val vec0_bytearr_list: ArrayList<ByteArray> = ArrayList<ByteArray>()
    private val epk_list : ArrayList<ByteArray> = ArrayList<ByteArray>()
    private val ks : KeyStore
    private val possible_values_count: Int

    init {
        when (varcon.vari){
             Variant.BASIC ->{
                 val allornot_1_flatarr = Base64.getUrlDecoder().decode(allornot_1)
                 val allornot_0_flatarr = Base64.getUrlDecoder().decode(allornot_0)
                 val vec1_flatarr = Base64.getUrlDecoder().decode(vec1)
                 val vec0_flatarr = Base64.getUrlDecoder().decode(vec0)
                 val epk_flatarr = Base64.getUrlDecoder().decode(serverepk)
                 for (i in 0..255){
                     allornot_1_bytearr_list.add(allornot_1_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                     allornot_0_bytearr_list.add(allornot_0_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                     vec1_bytearr_list.add(vec1_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                     vec0_bytearr_list.add(vec0_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                 }
                 for (i in 0..511){
                     epk_list.add(epk_flatarr.slice((i*33)..(i*33)+32).toByteArray() )
                 }
                 possible_values_count = 2
             }
            Variant.BYTE ->{
                val epk_flatarr = Base64.getUrlDecoder().decode(serverepk)
                val ciphertext_flatarr = Base64.getUrlDecoder().decode(vec1)
                val allornot_flatarr = Base64.getUrlDecoder().decode(allornot_0)
                val CHUNKSIZE = 32

                possible_values_count = 2.0.pow(8).toInt()
                val upperbound = ( possible_values_count *CHUNKSIZE)-1
                for (i in 0..upperbound ){
                    allornot_0_bytearr_list.add(allornot_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                    vec0_bytearr_list.add(ciphertext_flatarr.slice((i*32)..(i*32)+31).toByteArray())
                }

                //pow(2**WORDSIZE)*CHUNKSIZE
                for (i in 0..upperbound ) {
                    epk_list.add(epk_flatarr.slice((i*33)..(i*33)+32).toByteArray() )
                }
            }
        }



        val namedCurveParams = ECNamedCurveTable.getParameterSpec("secp256r1")
        val ellipticCurve = EllipticCurve(
            EC5Util.convertField(namedCurveParams.curve.field),
            namedCurveParams.curve.a.toBigInteger(),
            namedCurveParams.curve.b.toBigInteger()
        )
        ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        ecSpecSimple = ECParameterSpec(ellipticCurve, EC5Util.convertPoint(ecSpec.g), ecSpec.n, ecSpec.h.toInt())


        ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
    }

    fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

    private fun getCleanURL(url: String): String? {
        return url.replace("\\\\".toRegex(), "").trim { it <= ' ' }
    }
    fun xorByteArrays(array1: ByteArray, array2: ByteArray, len: Int): ByteArray {
        val result = ByteArray(len)
        for (i in 0 until len) {
            result[i] = (array1[i] xor array2[i])
        }
        return result
    }
    fun splitByteArrays(byteArray: ByteArray): Pair<ByteArray,ByteArray>{
        return Pair<ByteArray,ByteArray>(byteArray.sliceArray(0..15),byteArray.sliceArray(16..31))
    }
    fun deriveKey(finalsec: ByteArray, localsec: ByteArray): ByteArray{
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        return digest.digest(finalsec + localsec)
    }

    private fun getClientData(challenge:String): String{
        val ret = JSONObject()
        ret.put("type","webauthn.get")
        ret.put("challenge", challenge)
        ret.put("origin", "https://fido-delegation-demo.eastus.cloudapp.azure.com")

        return getCleanURL(ret.toString())!!
    }

    fun answerChallenge(challenge: String): String{
        var client_data_modified = JSONObject(Base64.getUrlDecoder().decode(client_data).decodeToString()) // json.loads( urlsafe_b64decode(client_data.encode('ascii')))
        client_data_modified.remove("challenge")
        client_data_modified.put("challenge", challenge)
//        val client_data_jsonstr = getCleanURL(client_data_modified.toString())!!
        val client_data_jsonstr = getClientData(challenge)
        Log.d(TAG, client_data_jsonstr)
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        val client_data_hash: ByteArray = digest.digest(client_data_jsonstr.toByteArray())

        Log.d(TAG,"signed message:" + (Base64.getUrlDecoder().decode(authenticator_data) + client_data_hash).toHex() )
        val s = when(varcon.vari){
            Variant.BASIC -> signMessage(Base64.getUrlDecoder().decode(authenticator_data) + client_data_hash)
            Variant.BYTE -> signMessageChunk(Base64.getUrlDecoder().decode(authenticator_data) + client_data_hash, 8)
        }
        val sig = ASN1ECDSA(ASN1Integer(r),ASN1Integer(s))
        val encoded_signature: ByteArray = sig.toASN1Primitive().encoded

        val responseJSONObject = JSONObject()
        responseJSONObject.put("authenticatorData", authenticator_data)
        responseJSONObject.put("clientDataJSON", Base64.getUrlEncoder().encodeToString(client_data_jsonstr.toByteArray()) )
        responseJSONObject.put("signature", Base64.getUrlEncoder().encodeToString(encoded_signature))
        responseJSONObject.put("userHandle", user_handle)

        val returnJSONObject =  JSONObject()
        returnJSONObject.put("id", credential_id)
        returnJSONObject.put("rawId", credential_id)
        returnJSONObject.put("response", responseJSONObject)
        returnJSONObject.put("type", "public-key")

        return returnJSONObject.toString()
    }

    //Decrypt until hiding_sign raw
    suspend fun decryptToRaw(encryptedBytes: ByteArray, vec_0_or_1: Int, pos:Int): ByteArray {
        val targetpk_bytes = epk_list[(pos*2)+vec_0_or_1 ]

        val privkey = ks.getKey(keyalias, null) as PrivateKey

        val receivedCompressedPublicKey: ECPoint = EC5Util.convertPoint(ecSpec!!.curve.decodePoint(targetpk_bytes))
        val receivedPublicKey: PublicKey = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(receivedCompressedPublicKey, ecSpecSimple))

//        val startTime = System.currentTimeMillis()
        val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        keyAgreement.init(privkey)
        keyAgreement.doPhase(receivedPublicKey, true)
        val secretbytes = keyAgreement.generateSecret()
//        val endTime = System.currentTimeMillis()
//        val elapsedTime = endTime - startTime
//        Log.d(TAG,"Decrypt:$elapsedTime")

        for (i in 0..31){
            encryptedBytes[i] = (secretbytes[i] xor encryptedBytes[i])
        }
        return encryptedBytes!!
    }

    suspend fun decryptToRaw_ByteInstance(encryptedBytes: ByteArray, vec_pos: Int, pos:Int, wordSize: Int): ByteArray {
        val targetpk_bytes = epk_list[(pos*possible_values_count)+vec_pos ]

        val privkey = ks.getKey(keyalias, null) as PrivateKey

        val receivedCompressedPublicKey: ECPoint = EC5Util.convertPoint(ecSpec!!.curve.decodePoint(targetpk_bytes))
        val receivedPublicKey: PublicKey = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(receivedCompressedPublicKey, ecSpecSimple))

        //        val startTime = System.currentTimeMillis()
        val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        keyAgreement.init(privkey)
        keyAgreement.doPhase(receivedPublicKey, true)
        val secretbytes = keyAgreement.generateSecret()
        //        val endTime = System.currentTimeMillis()
        //        val elapsedTime = endTime - startTime
        //        Log.d(TAG,"Decrypt:$elapsedTime")

        for (i in 0..31){
            encryptedBytes[i] = (secretbytes[i] xor encryptedBytes[i])
        }
        return encryptedBytes!!
    }

    fun signMessage(message: ByteArray): BigInteger{
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        val hash: ByteArray = digest.digest(message)
        Log.d(TAG, "MessageHashed:"+ hash.toHex())

        var hash_bits = ArrayList<Int>(0)
        var hash_bits_str = ""

        //Assuming BigEndianness for the HashByteArray
        var counter = 0
        for (byte in hash)
            for (i in 0..7)
                hash_bits.add( (byte.toInt().shr(7-i)).and(0x1) )
                hash_bits_str += hash_bits[counter].toString()
                counter +=1
        hash_bits.reverse()

        val curve: ECCurve = CustomNamedCurves.getByName("secp256r1").getCurve()
        val order = curve.order
        //val generator = CustomNamedCurves.getByName("secp256k1").g

        var rolling_sum = BigInteger.ZERO
        //Recovery All-or-Nothing Shared Key
        var final_sec = ByteArray(16)
        val allornot_localsec = ArrayList<ByteArray>()

        val startTime = System.currentTimeMillis()
        val rawbytes = Array<ByteArray>(256) { _ -> ByteArray(32)}
        val decryptedrawbytes = runBlocking  {
            rawbytes.mapIndexed { i, _ ->
                async(Dispatchers.Default) {
                    if (hash_bits[i] == 1)
                        //Intentional 1 and 0 swapped in vec_0_or_1, save inversion
                        decryptToRaw(allornot_1_bytearr_list[i], 0,i)
                    else
                        decryptToRaw(allornot_0_bytearr_list[i], 1,i)
                }
            }.awaitAll()
        }
        for (i in 0..255){
            val (shared_key_share,localsec) = splitByteArrays(decryptedrawbytes[i])
            final_sec = xorByteArrays(final_sec,shared_key_share,16)
            allornot_localsec.add(localsec)
        }

        val endTime = System.currentTimeMillis()
        val elapsedTime = endTime - startTime
        Log.d(TAG, "Elapsed Time for 256 Decryption: $elapsedTime milliseconds")

        //Decrypt Hiding_sign
        for (i in 0..255) {
            val key = deriveKey(final_sec, allornot_localsec[i])
            //Log.d(TAG, "KeyDerived"+hash_bits[i].toString()+":"+i.toString()+ ":"+Base64.getUrlEncoder().encodeToString(key) )
            if (hash_bits[i] == 1){
                rolling_sum += BigInteger(1,xorByteArrays(key,vec1_bytearr_list[i],32)).mod(order)
            }
            else if (hash_bits[i] == 0){
                rolling_sum += BigInteger(1,xorByteArrays(key,vec0_bytearr_list[i],32)).mod(order)
            }
            else
                Log.e(TAG, "hash_bits is wrong")
        }

        val s = (part1 + rolling_sum) % order

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        ks.deleteEntry(keyalias)

        Log.d(TAG, "Computed signed s:$s")

        val rbyte = this.r.toByteArray()
        if (rbyte.size == 33){
            this.r = BigInteger(1,xorByteArrays(rbyte.sliceArray(1..32),deriveKey(final_sec,ByteArray(0)),32))
        }
        else{
            val rbyte_pad = ByteArray(32-rbyte.size) + rbyte
            this.r = BigInteger(1,xorByteArrays(rbyte_pad,deriveKey(final_sec,ByteArray(0)),32))
        }

        return s
    }

    fun signMessageChunk(message: ByteArray, wordSize: Int): BigInteger{
        val digest: MessageDigest = MessageDigest.getInstance("SHA-256")
        val hash: ByteArray = digest.digest(message)
        Log.d(TAG, "MessageHashed:"+ hash.toHex())
        var hash_chunk = ArrayList<Int>(0)
        var hash_bits_str = ""
        //Assuming BigEndianness for the HashByteArray
        for (byte in hash)
            hash_chunk.add(byte.toUByte().toInt())
        hash_chunk.reverse() //Little Endian (bit) is used when computed the splitted signature

        val curve: ECCurve = CustomNamedCurves.getByName("secp256r1").getCurve()
        val order = curve.order

        var rolling_sum = BigInteger.ZERO
        //Recovery All-or-Nothing Shared Key
        var final_sec = ByteArray(16)
        val allornot_localsec = ArrayList<ByteArray>()

        val startTime = System.currentTimeMillis()
        val chunksize = 256/wordSize
        val rawbytes = Array<ByteArray>(chunksize) { _ -> ByteArray(32)}

        val decryptedrawbytes = runBlocking  {
            rawbytes.mapIndexed { i, _ ->
                async(Dispatchers.Default) {
                    //(pos*wordSize*2)+vec_pos
                    decryptToRaw_ByteInstance(allornot_0_bytearr_list[ (i*possible_values_count)+hash_chunk[i] ],hash_chunk[i],i,wordSize)
                }
            }.awaitAll()
        }

        for (i in 0..chunksize-1){
            val (shared_key_share,localsec) = splitByteArrays(decryptedrawbytes[i])
            final_sec = xorByteArrays(final_sec,shared_key_share,16)
            allornot_localsec.add(localsec)
        }
        val endTime = System.currentTimeMillis()
        val elapsedTime = endTime - startTime
        Log.d(TAG, "Elapsed Time for $chunksize Decryption: $elapsedTime milliseconds")

        //Decrypt Hiding_sign
        for (i in 0..chunksize-1) {
            val key = deriveKey(final_sec, allornot_localsec[i])
            //Log.d(TAG, "KeyDerived"+hash_bits[i].toString()+":"+i.toString()+ ":"+Base64.getUrlEncoder().encodeToString(key) )
            rolling_sum += BigInteger(1,xorByteArrays(key,vec0_bytearr_list[ (i*possible_values_count)+hash_chunk[i] ],32)).mod(order)
       }

        val s = (part1 + rolling_sum) % order

        Log.d(TAG, "Computed signed s:$s")

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        ks.deleteEntry(keyalias)

        val rbyte = this.r.toByteArray()
        if (rbyte.size == 33){
            this.r = BigInteger(1,xorByteArrays(rbyte.sliceArray(0..31),deriveKey(final_sec,ByteArray(0)),32))
        }
        else{
            val rbyte_pad = ByteArray(32-rbyte.size) + rbyte
            this.r = BigInteger(1,xorByteArrays(rbyte_pad,deriveKey(final_sec,ByteArray(0)),32))
        }

        return s

    }
}