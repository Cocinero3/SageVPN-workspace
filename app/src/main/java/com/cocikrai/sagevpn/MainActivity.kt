package com.cocikrai.sagevpn

import android.annotation.SuppressLint
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TableLayout
import android.widget.TableRow
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.LiveData

class MainActivity : AppCompatActivity() {

    private lateinit var btStartVPN:Button
    private lateinit var btStopVPN:Button
    private lateinit var tableData: TableLayout
    private var packetArray: ArrayList<Packet> = ArrayList()

    @SuppressLint("UnsafeIntentLaunch")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        btStartVPN = findViewById(R.id.btStart)
        btStopVPN = findViewById(R.id.btStop)
        tableData = findViewById(R.id.dataTable)

        val livePackets: LiveData<Packet> = SageService.packetLiveData

        livePackets.observe(this) { newPacket ->
            packetArray.add(newPacket)
            val newRow = TableRow(this)
            newRow.setId(packetArray.size)
            val col1 = TextView(this)
            col1.setPadding(3,3,3,3)
            col1.width = 362
            val col2 = TextView(this)
            col2.setPadding(3,3,3,3)
            col2.gravity = 5
            if(newPacket.ipv4Headers != null) {
                col1.text = newPacket.ipv4Headers!!.sourceIPArray.joinToString(".") { "%d".format(it) }
                col2.text = newPacket.ipv4Headers!!.desIPArray.joinToString(".") { "%d".format(it) }
            } else {
                col1.text = newPacket.ipv6Headers!!.getSourceString()
                col2.text = newPacket.ipv6Headers!!.getDestinationString()
            }

            newRow.addView(col1)
            newRow.addView(col2)

            tableData.addView(newRow)
        }


        btStartVPN.setOnClickListener{
            intent = VpnService.prepare(this)
            Log.d("SAGEVPN", "intent prepare has been triggered for Sage")
            if (intent != null) {
                Log.d("SAGEVPN", "starting activity")
                startActivityForResult(intent, 0, null)
            } else {
                onActivityResult(0, RESULT_OK, null)
            }
        }

        btStopVPN.setOnClickListener{
            Log.d("SAGEVPN", "Stopping SageVPN service")
            stopService(getServiceIntent())
        }

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        Log.d("SAGEVPN", "triggering on activity result")
        Log.d("SAGEVPN", request.toString())
        Log.d("SAGEVPN", result.toString())
        Log.d("SAGEVPN", data.toString())

        if (result == RESULT_OK) {
            Log.d("SAGEVPN", getServiceIntent().toString())
            try {

                startService(getServiceIntent())
            } catch (e: Throwable) {
                Log.d("SAGEVPN", e.toString())
            }

        }
        super.onActivityResult(request, result, data)

    }

    private fun getServiceIntent(): Intent {
        return Intent(this, SageService::class.java)
    }
}