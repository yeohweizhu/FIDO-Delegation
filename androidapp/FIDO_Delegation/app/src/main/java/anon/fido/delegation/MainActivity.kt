package anon.fido.delegation

import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.JsonReader
import android.util.Log
import android.view.View
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.size
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import anon.fido.delegation.service.ReplyService
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.InputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.net.*
import java.util.*
import kotlin.collections.ArrayList
import kotlin.math.pow
import kotlin.math.sqrt


class MainActivity : AppCompatActivity() {
    private val TAG = "DelegatedMain"
    private var profileAdapter : FidoProfileAdapter?= null

    @RequiresApi(Build.VERSION_CODES.S)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)


        val challenge = this.intent?.data?.getQueryParameter("challenge")
        val getfido = this.intent?.data?.getQueryParameter("cmdgetfido")
        if (challenge != null){
            //Authenticate using Delegated FIDO
            Log.d(TAG, "Challenge:" + challenge)
            PersistencyManager.challenge = challenge
            //            authenticate()
        }
        else if (getfido!=null){
            //Superceded by ProfileAdapter
        }
        else{
            //
        }

//        PersistencyManager.clear(this)
        val dataset = PersistencyManager.load(this)
        profileAdapter = FidoProfileAdapter(dataset, this)

        val recyclerView: RecyclerView = findViewById(R.id.recyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = profileAdapter

//        benchmark_delegate(VariantConfig.BasicInstance())
//        benchmark_delegate(VariantConfig.ByteInstance())
//        benchmark_sign(VariantConfig.BasicInstance())
//        benchmark_sign(VariantConfig.ByteInstance()
//        benchmark_sign_attest()
//        benchmark_strongbox(VariantConfig.BasicInstance())
//        benchmark_strongbox(VariantConfig.ByteInstance())
//        benchmark_strongbox_attest()
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun benchmark_sign(varcon :VariantConfig){
        this.lifecycleScope.launch {
            val elapsedTimeArr = ArrayList<Long>()
            for (i in 0..99){
                val (response_output,keystore_alias) = callToken(varcon.count)
                Log.d(TAG,response_output)
                val gson = Gson()
                val it = gson.fromJson(response_output, DelegatedData::class.java)
                it.keyalias = keystore_alias
                val startTime = System.currentTimeMillis()
                val authReply = DelegatedFIDOSignature(
                    it.r,it.part1,it.hiding_sign,it.hiding_sign_vec2, it.allornot_1, it.allornot_0,it.serverepk,
                    it.credential_id,it.user_handle,it.client_data,it.authenticator_data, it.keyalias, this@MainActivity, varcon).answerChallenge(PersistencyManager.challenge)
                val endTime = System.currentTimeMillis()
                val elapsedTime = endTime - startTime
                elapsedTimeArr.add(elapsedTime)
                Log.d(TAG, "Elapsed Time for Entire Signing: $elapsedTime milliseconds")
            }
            val average = elapsedTimeArr.average()
            val sqdDif = elapsedTimeArr.map { (it - average).pow(2.0) }.sum()
            Log.d(TAG, "Avg: $average")
            Log.d(TAG, "STD: " + sqrt(sqdDif / (elapsedTimeArr.size) ).toString())
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun benchmark_sign_attest(){
        this.lifecycleScope.launch {
            val elapsedTimeArr = ArrayList<Long>()
            for (i in 0..99){
                val startTime = System.currentTimeMillis()
                val otm = OneTimeMemory(256)
                val attestation = otm.getAttestation()
                val endTime = System.currentTimeMillis()
                val elapsedTime = endTime - startTime
                elapsedTimeArr.add(elapsedTime)
                otm.deleteKey()
                Log.d(TAG, "Elapsed Time for Attestation/KeyGen: $elapsedTime milliseconds")
            }
            val average = elapsedTimeArr.average()
            val sqdDif = elapsedTimeArr.map { (it - average).pow(2.0) }.sum()
            Log.d(TAG, "Avg: $average")
            Log.d(TAG, "STD: " + sqrt(sqdDif / (elapsedTimeArr.size) ).toString())
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun benchmark_strongbox_attest(){
        this.lifecycleScope.launch {
            val elapsedTimeArr = ArrayList<Long>()
            for (i in 0..99){
                val startTime = System.currentTimeMillis()
                val otm = OneTimeMemory(256)
                val attestation = otm.getAttestationStrongbox()
                val endTime = System.currentTimeMillis()
                val elapsedTime = endTime - startTime
                elapsedTimeArr.add(elapsedTime)
                otm.deleteKey()
                Log.d(TAG, "Elapsed Time for Attestation/KeyGen: $elapsedTime milliseconds")
            }
            val average = elapsedTimeArr.average()
            val sqdDif = elapsedTimeArr.map { (it - average).pow(2.0) }.sum()
            Log.d(TAG, "Avg: $average")
            Log.d(TAG, "STD: " + sqrt(sqdDif / (elapsedTimeArr.size) ).toString())
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun benchmark_strongbox(varcon :VariantConfig){
        this.lifecycleScope.launch {
            val elapsedTimeArr = ArrayList<Long>()
            for (i in 0..99){
                val (response_output,keystore_alias) = callToken_strongbox(varcon.count)
                Log.d(TAG, "$i: $response_output")
                val gson = Gson()
                val it = gson.fromJson(response_output, DelegatedData::class.java)
                it.keyalias = keystore_alias
                val startTime = System.currentTimeMillis()
                val authReply = DelegatedFIDOSignature(
                    it.r,it.part1,it.hiding_sign,it.hiding_sign_vec2, it.allornot_1, it.allornot_0,it.serverepk,
                    it.credential_id,it.user_handle,it.client_data,it.authenticator_data, it.keyalias, this@MainActivity, varcon).answerChallenge(PersistencyManager.challenge)
                val endTime = System.currentTimeMillis()
                val elapsedTime = endTime - startTime
                elapsedTimeArr.add(elapsedTime)
                Log.d(TAG, "Elapsed Time for Entire Signing: $elapsedTime milliseconds")
            }
            val average = elapsedTimeArr.average()
            val sqdDif = elapsedTimeArr.map { (it - average).pow(2.0) }.sum()
            Log.d(TAG, "Avg: $average")
            Log.d(TAG, "STD: " + sqrt(sqdDif / (elapsedTimeArr.size) ).toString())
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun benchmark_delegate(varcon :VariantConfig){
        this.lifecycleScope.launch {
            callTokenBenchmark(varcon.count)
        }
    }

    override fun onPause() {
        Log.d(TAG,"onPause")
        PersistencyManager.save(this)
        super.onPause()
    }

    @RequiresApi(Build.VERSION_CODES.S)
    suspend fun callToken(counter_count: Int): Pair<String,String> = withContext(Dispatchers.IO) {
        val otm = OneTimeMemory(counter_count)
        val attestation = otm.getAttestation()
        val keystore_alias = otm.getKeyAlias()
//        otm.deleteKey()
        val url = URL("https://fido-delegation-demo.eastus.cloudapp.azure.com:5000/api/delegatedpresig?attestation=" + attestation)
        with(url.openConnection() as HttpURLConnection) {
            requestMethod = "GET"
            Log.d(TAG,"\nSent 'GET' request to URL : $url; Response Code : $responseCode")
            inputStream.bufferedReader().use {
                return@withContext Pair<String, String>(it.lines().reduce { acc, s -> acc+s}.orElse(""),keystore_alias)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    suspend fun callToken_strongbox(counter_count:Int): Pair<String,String> = withContext(Dispatchers.IO) {
        val otm = OneTimeMemory(counter_count)
        val attestation = otm.getAttestationStrongbox()
        val keystore_alias = otm.getKeyAlias()
        val url = URL("https://fido-delegation-demo.eastus.cloudapp.azure.com:5000/api/delegatedpresig?attestation=" + attestation)
        with(url.openConnection() as HttpURLConnection) {
            requestMethod = "GET"
            Log.d(TAG,"\nSent 'GET' request to URL : $url; Response Code : $responseCode")
            inputStream.bufferedReader().use {
                return@withContext Pair<String, String>(it.lines().reduce { acc, s -> acc+s}.orElse(""),keystore_alias)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    suspend fun callTokenBenchmark(counter_count: Int): Pair<String,String> = withContext(Dispatchers.IO) {
        val otm = OneTimeMemory(counter_count)
        otm.deleteKey()
        val attestation = otm.getAttestation()
        val url = URL("https://fido-delegation-demo.eastus.cloudapp.azure.com:5000/api/benchmarkdelegate?attestation=" + attestation)
        with(url.openConnection() as HttpURLConnection) {
            requestMethod = "GET"
            inputStream.bufferedReader().use {
                return@withContext Pair<String, String>("","")
            }
        }
    }
}