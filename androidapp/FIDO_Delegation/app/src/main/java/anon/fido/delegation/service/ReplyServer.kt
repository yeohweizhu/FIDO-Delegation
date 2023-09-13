package anon.fido.delegation.service

import android.util.Log
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import fi.iki.elonen.NanoHTTPD

class ReplyServer(private val dataJsonStr: String, private val challenge: String) : NanoHTTPD(8080) {
    val TAG = "ReplyServer"

    var isDataFetched = false
        private set

    private fun addCorsHeaders(resp: Response) {
        resp.addHeader("Access-Control-Allow-Origin", "*")
        //            resp.addHeader("Access-Control-Allow-Origin", "https://fido-delegation-demo.eastus.cloudapp.azure.com");
        resp.addHeader("Access-Control-Max-Age", "3628800")
        resp.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        resp.addHeader("Access-Control-Allow-Headers", "*")
    }

    override fun serve(session: IHTTPSession): Response {
        if (session.method == Method.OPTIONS) {
            val resp = newFixedLengthResponse(Response.Status.OK, MIME_PLAINTEXT, "success")
            addCorsHeaders(resp)
            return resp
        }
        if (!session.parameters.containsKey("challenge")) {
            return newFixedLengthResponse(
                Response.Status.BAD_REQUEST,
                MIME_PLAINTEXT,
                "Missing challenge"
            )
        }
        return if (session.parameters["challenge"]!![0] == challenge) {
            try {
                Log.i("AppReply Callback", "Serving data")
                val dataJson = ObjectMapper().writeValueAsString(dataJsonStr)
                Log.d("AppReply Callback", "Sending $dataJson")
                isDataFetched = true
                val resp = newFixedLengthResponse(Response.Status.OK, "application/json", dataJson)
                resp.addHeader("Cache-Control", "no-cache, no-store, must-revalidate")
                addCorsHeaders(resp)
                resp
            } catch (e: JsonProcessingException) {
                newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, "")
            }
        } else {
            Log.d(TAG,session.parameters["challenge"]!![0])
            Log.d(TAG,challenge)
//            val resp = newFixedLengthResponse(Response.Status.OK, MIME_PLAINTEXT, "success")
//            addCorsHeaders(resp)
//            return resp
            newFixedLengthResponse(Response.Status.BAD_REQUEST, MIME_PLAINTEXT, "")
        }
    }

    init {
        start(SOCKET_READ_TIMEOUT, true)
        println("\nRunning! Point your browsers to http://localhost:8080/ \n")
    }
}