package anon.fido.delegation

import android.content.Context
import android.content.DialogInterface
import android.graphics.Color
import android.os.Build
import android.os.SystemClock
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.cardview.widget.CardView
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.RecyclerView
import anon.fido.delegation.service.ReplyService
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.random.Random

class FidoProfileAdapter(val dataSet: ArrayList<DelegatedData>, private val mainAct: MainActivity):
    RecyclerView.Adapter<RecyclerView.ViewHolder>() {
    val TAG = "FidoProfileAdapter"
    val config = VariantConfig.BasicInstance()

    var mLastClickTime = 0L
    fun isClickRecently(): Boolean {
        if (SystemClock.elapsedRealtime() - mLastClickTime < 1000) {
            return true
        }
        mLastClickTime = SystemClock.elapsedRealtime()
        return false
    }

    val fetching_dialog : AlertDialog?
    val computesig_dialog: AlertDialog?

    init{
        val builder : AlertDialog.Builder?
        builder= mainAct?.let {
            AlertDialog.Builder(it)
        }
        builder?.setMessage("Fetching...")?.setTitle("Getting Delegated FIDO")
        fetching_dialog = builder?.apply {
        }?.create()

        val builder2 : AlertDialog.Builder?
        builder2= mainAct?.let {
            AlertDialog.Builder(it)
        }
        builder2?.setMessage("Computing...")?.setTitle("Computing Signature")
        computesig_dialog = builder2?.apply {
        }?.create()
    }

    /**
     * Provide a reference to the type of views that you are using
     * (custom ViewHolder)
     */
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val textViewName: TextView
        val textViewBalance: TextView
        val cardView : CardView
        val colorArr : Array<String>

        init {
            // Define click listener for the ViewHolder's View
            textViewName = view.findViewById(R.id.textViewName)
            textViewBalance = view.findViewById(R.id.textViewBalance)
            cardView = view.findViewById(R.id.cardView)
            colorArr = view.resources.getStringArray(R.array.colorsarr)
        }
    }

    class ViewHolder2(view: View) : RecyclerView.ViewHolder(view) {
        val cardView : CardView
        val colorArr : Array<String>


        init {
            // Define click listener for the ViewHolder's View
            colorArr = view.resources.getStringArray(R.array.colorsarr)
            cardView = view.findViewById(R.id.cardView)
        }
    }

    // Create new views (invoked by the layout manager)
    override fun onCreateViewHolder(viewGroup: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        // Create a new view, which defines the UI of the list item


        if (viewType == 0){
            val view = LayoutInflater.from(viewGroup.context)
                .inflate(R.layout.row_item, viewGroup, false)

            return ViewHolder(view) as RecyclerView.ViewHolder
        }
        else{
            //Last one different view
            val view = LayoutInflater.from(viewGroup.context)
                .inflate(R.layout.row_item_add, viewGroup, false)

            return ViewHolder2(view) as RecyclerView.ViewHolder
        }
    }

    // Replace the contents of a view (invoked by the layout manager)
    @RequiresApi(Build.VERSION_CODES.S)
    override fun onBindViewHolder(viewHolder: RecyclerView.ViewHolder, position: Int) {

        // Get element from your dataset at this position and replace the
        // contents of the view with that element
        if (viewHolder.itemViewType == 0){
            viewHolder as ViewHolder
            viewHolder.textViewName.text = dataSet[position].userName
            viewHolder.textViewBalance.text = "user_id: " + dataSet[position].balance.toString()
            viewHolder.cardView.setCardBackgroundColor(Color.parseColor(viewHolder.colorArr[position%5]))
            viewHolder.cardView.setOnClickListener {
                if (!isClickRecently()){
                    Log.d(TAG,"Clicked")
                    computesig_dialog?.show()
                    mainAct.lifecycleScope.launch(Dispatchers.Default){
                        val it = dataSet[position]
                        val startTime = System.currentTimeMillis()
                        val authReply = DelegatedFIDOSignature(
                            it.r,it.part1,it.hiding_sign,it.hiding_sign_vec2, it.allornot_1, it.allornot_0,it.serverepk,
                            it.credential_id,it.user_handle,it.client_data,it.authenticator_data, it.keyalias, mainAct, config
                        ).answerChallenge(PersistencyManager.challenge)
                        val endTime = System.currentTimeMillis()
                        val elapsedTime = endTime - startTime
                        Log.d(TAG, "Elapsed Time for Entire Signing: $elapsedTime milliseconds")
                        ReplyService.startService(mainAct,PersistencyManager.challenge, authReply)
                        computesig_dialog?.cancel()
                        dataSet.removeAt(position)
                        mainAct.finish()
                    }
                }
            }
        }
        else{
            viewHolder as ViewHolder2
            viewHolder.cardView.setCardBackgroundColor(Color.parseColor(viewHolder.colorArr[position%5]))
            viewHolder.cardView.setOnClickListener {
                if (!isClickRecently()){
                    fetching_dialog?.show()
                    viewHolder.cardView.isEnabled = false
                    mainAct.lifecycleScope.launch {
                        val (response_output,keystore_alias) = mainAct.callToken(config.count)
                        Log.d(TAG,response_output)
                        val gson = Gson()
                        val delegated_data = gson.fromJson(response_output, DelegatedData::class.java)
                        delegated_data.keyalias = keystore_alias

//                        val positionToAdd= itemCount
//                        this@FidoProfileAdapter.dataSet.add(itemCount-1,delegated_data)
                        PersistencyManager.data.add(itemCount-1,delegated_data)
                        this@FidoProfileAdapter.notifyItemInserted(itemCount)
                        fetching_dialog?.cancel()
                        viewHolder.cardView.isEnabled = true
                    }
                }
            }
        }
    }

    // Return the size of your dataset (invoked by the layout manager)
    override fun getItemCount() = dataSet.size

    override fun getItemViewType(position: Int): Int {
        return if ((itemCount -1)==position) 1 else 0
    }



}