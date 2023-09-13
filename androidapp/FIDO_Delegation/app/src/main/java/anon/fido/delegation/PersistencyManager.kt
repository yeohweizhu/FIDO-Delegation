package anon.fido.delegation

import android.content.Context
import android.util.Log
import com.google.gson.Gson

class PersistencyManager {
    companion object{
        val TAG = "Persistent"
        var data: ArrayList<DelegatedData> = ArrayList<DelegatedData>()
        val challengeID = "challenge"
        var challenge = "placeholder"
        val dataJsonID = "data"

        fun save(context: Context){
            Log.d(TAG, "Try to Save of size: " + data.size)
            val gson = Gson()
            val tosave = gson.toJson(data)
            Log.d(TAG, tosave)

            val sharedPreference =  context.getSharedPreferences("SAVE", Context.MODE_PRIVATE)
            var editor = sharedPreference.edit()
            editor.putString("save",tosave)
            editor.commit()

        }

        fun load(context: Context): ArrayList<DelegatedData> {
            val sharedPreference =  context.getSharedPreferences("SAVE", Context.MODE_PRIVATE)
            var saveData = sharedPreference.getString("save", "")
            if (saveData != null) {
                Log.d(TAG, saveData)
            }
            if (saveData != ""){
                //sharedPreference.edit().clear().commit()
                val gson = Gson()
                data = gson.fromJson(saveData, Array<DelegatedData>::class.java).toCollection(ArrayList())
                return data
            }
            else{
                data.add(getDefaultDelegatedData())
                return data
            }

        }

        fun clear(context:Context){
            val sharedPreference =  context.getSharedPreferences("SAVE", Context.MODE_PRIVATE)
            var editor = sharedPreference.edit()
            editor.clear().commit()
        }
    }
}