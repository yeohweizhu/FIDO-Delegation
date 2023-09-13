package anon.fido.delegation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

//OneTime Memory from n-times used key
@RequiresApi(Build.VERSION_CODES.S)
class OneTimeMemory (val MAX_COUNTER:Int) {
    private var keyAlias: String
    private val TAG = "OneTimeMemory"
    private fun bytesToHex(data: ByteArray?): String {
        if (data == null) {
            return "NullObjRef"
        }
        val hex = StringBuilder(data.size * 2)
        for (b in data) hex.append(String.format("%02x",  (b.toInt() and 0xff).toByte() ))
        return hex.toString()
    }

    init {
        //Log.i(TAG, "Public: " + bytesToHex(kp.public.encoded))
       // Log.i(TAG, "Public" + cert_x509array.size.toString() +" : " + cert.toString());
        keyAlias = Random.nextInt().toString()
//        keyAlias = "DEBUG"
    }

    fun getAttestation(): String{
        val att_challenge = byteArrayOf(0x40, 0x41, 0x42)

        val keypairgen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val newSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("p-256"))
            .setAttestationChallenge(att_challenge)
            .setMaxUsageCount(MAX_COUNTER)
            .build()
        keypairgen.initialize(newSpec)
        val kp = keypairgen.generateKeyPair()

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
//        Log.d(TAG,"CertSize:Start")
        ks.load(null)
        val cert = ks.getCertificateChain(keyAlias)
        var cert_x509array = ArrayList<ByteArray>()
        for (i in cert.indices) {
            val ct = cert[i]
            cert_x509array.add( (ct as X509Certificate).encoded)
        }
        val cert_x509array_b64 = ArrayList<String>()
        for (cert_entry in cert_x509array){
//            Log.d(TAG,"CertSize:" + cert_entry.size)
            cert_x509array_b64.add(Base64.getUrlEncoder().encodeToString(cert_entry))
        }
        val gson = Gson()
        val att_data = gson.toJson(AttestationData(cert_x509array_b64), AttestationData::class.java)
//        Log.d(TAG,"CertSize:End")

//        ks.deleteEntry(keyAlias)

        return att_data
    }

    fun getAttestationStrongbox(): String{
        val att_challenge = byteArrayOf(0x40, 0x41, 0x42)
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)

        val keypairgen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val newSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("p-256"))
            .setAttestationChallenge(att_challenge)
            .setMaxUsageCount(MAX_COUNTER)
            .setIsStrongBoxBacked(true)
            .build()
        keypairgen.initialize(newSpec)
        val kp = keypairgen.generateKeyPair()

        val cert = ks.getCertificateChain(keyAlias)
        var cert_x509array = ArrayList<ByteArray>()
        for (i in cert.indices) {
            val ct = cert[i]
            cert_x509array.add( (ct as X509Certificate).encoded)
        }
        val cert_x509array_b64 = ArrayList<String>()
        for (cert_entry in cert_x509array){
            cert_x509array_b64.add(Base64.getUrlEncoder().encodeToString(cert_entry))
        }
        val gson = Gson()
        val att_data = gson.toJson(AttestationData(cert_x509array_b64), AttestationData::class.java)

        //        ks.deleteEntry(keyAlias)

        return att_data
    }



    fun getKeyAlias(): String{
        return keyAlias
    }

    fun deleteKey(){
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        ks.deleteEntry(keyAlias)
    }
}