package anon.fido.delegation.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import anon.fido.delegation.PersistencyManager
import java.io.IOException

class ReplyService : Service() {

    private var server: ReplyServer? = null
    private val TAG = "ReplyService"

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        val challenge = intent.getStringExtra(PersistencyManager.challengeID)
        val dataJson = intent.getStringExtra(PersistencyManager.dataJsonID)
        Log.i(TAG, "Challenge: $challenge")
        Log.i(TAG, "Data: $dataJson")
        try {
            server = ReplyServer(dataJson!!, challenge!!)
        } catch (e: IOException) {
            e.printStackTrace()
        }
        Thread(Runnable {
            while (true) {
                try {
                    Thread.sleep(1000)
                    if (server!!.isDataFetched) {
                        Log.i(TAG, "Killing service")
                        server!!.stop()
                        stopSelf()
                        return@Runnable
                    } else {
                        Log.i(TAG, "Service still not served")
                    }
                } catch (e: InterruptedException) {
                    e.printStackTrace()
                }
            }
        }).start()
        return START_NOT_STICKY
    }

    companion object{
        fun startService(context : Context, challenge: String, dataJson: String){
            val mIntent = Intent(context, ReplyService::class.java)
            mIntent.putExtra(PersistencyManager.challengeID, challenge)
            mIntent.putExtra(PersistencyManager.dataJsonID, dataJson)
            context.startService(mIntent)
        }
    }

    override fun onBind(intent: Intent?): IBinder? {
        //No binding
        return null
    }
}