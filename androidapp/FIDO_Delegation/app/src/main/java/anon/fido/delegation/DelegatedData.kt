package anon.fido.delegation

//import org.bouncycastle.jce.spec.ECParameterSpec
import android.util.Log
import androidx.annotation.RequiresApi
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertField
import org.bouncycastle.jce.ECNamedCurveTable
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.*
import java.util.*
import javax.crypto.KeyAgreement
import kotlin.experimental.xor


data class DelegatedData(
    val userName: String,
    val balance: Int,
    val credential_id: String,
    val user_handle: String,
    val client_data: String,
    val authenticator_data: String,
    val r: BigInteger,
    val part1: BigInteger,
    val hiding_sign: String,
    val hiding_sign_vec2: String,
    val serverepk: String,
    val allornot_1: String,
    val allornot_0: String,
    var keyalias: String
)

data class AttestationData(
    val att:ArrayList<String>
)

data class AttestationDataNested(
    val data:ArrayList<AttestationData>
)

fun getDefaultDelegatedData(): DelegatedData{
    return DelegatedData("Default",0,"", "", "","",BigInteger.ZERO,BigInteger.ZERO,"","","","", "","")
}