package com.cocikrai.sagevpn

import android.annotation.SuppressLint
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.TableLayout
import android.widget.TableRow
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.LiveData
import kotlin.experimental.and

class MainActivity : AppCompatActivity() {

    private lateinit var btStartVPN:Button
    private lateinit var btStopVPN:Button
    private lateinit var tableData: TableLayout
    private lateinit var btBlacklist:Button
    private lateinit var blacklistText: EditText
    private var packetArray: ArrayList<Packet> = ArrayList()
    private var blacklistIps: ArrayList<String> = ArrayList()

    @SuppressLint("UnsafeIntentLaunch")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        btStartVPN = findViewById(R.id.btStart)
        btStopVPN = findViewById(R.id.btStop)
        btBlacklist = findViewById(R.id.blacklistButton)
        tableData = findViewById(R.id.dataTable)
        blacklistText = findViewById(R.id.textInput)

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
                col1.text = newPacket.ipv4Headers!!.sourceIPArray.joinToString(".") { "%d".format(it.toInt() and 0xFF) }
                col2.text = newPacket.ipv4Headers!!.desIPArray.joinToString(".") { "%d".format(it.toInt() and 0xFF) }
            } else {
                col1.text = newPacket.ipv6Headers!!.getSourceString()
                col2.text = newPacket.ipv6Headers!!.getDestinationString()
            }

            if(!blacklistIps.contains(col2.text.toString())) {
                newRow.addView(col1)
                newRow.addView(col2)

                newRow.setOnClickListener{
                    showPopup(it, newPacket)
                }

                tableData.addView(newRow)
            }

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
            val msg = getServiceIntent()
            msg.putExtra("block", "stop")
            startService(msg)
        }

        btBlacklist.setOnClickListener{
            val blockIP: String = blacklistText.text.toString()
            blacklistIps.add(blockIP)
            val msg = getServiceIntent()
            msg.putExtra("block", blockIP)
            startService(msg)
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

    private fun showPopup(anchorView: View, packet: Packet) {
        // Create the popup content programmatically
        val popupContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            setPadding(20, 20, 20, 20)

            addView(TextView(this@MainActivity).apply {
                text = "Source IP: ${packet.srcIpString}"
                textSize = 18f
                setTextColor(Color.BLACK)
            })

            addView(TextView(this@MainActivity).apply {
                text = "Destination IP: ${packet.destIpString}"
                textSize = 18f
                setTextColor(Color.BLACK)
            })

            addView(TextView(this@MainActivity).apply {
                text = "Source Port: ${packet.sourcePort}"
                textSize = 18f
                setTextColor(Color.BLACK)
            })

            addView(TextView(this@MainActivity).apply {
                text = "Destination Port: ${packet.destPort}"
                textSize = 18f
                setTextColor(Color.BLACK)
            })

            val whoIsLink = "https://www.whois.com/whois/" + packet.destIpString
            addView(TextView(this@MainActivity).apply {
                text = "Whois Lookup"
                textSize = 18f
                setTextColor(Color.BLUE)
                setOnClickListener {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(whoIsLink))
                    context.startActivity(intent)
                }
            })

            addView(TextView(this@MainActivity).apply {
                text = "Payload: ${packet.backBuffer.joinToString(" ") { "%02X".format(it) }}"
                textSize = 18f
                setTextColor(Color.BLACK)
            })

        }

        // Create PopupWindow with the programmatically created view
        val popupWindow = PopupWindow(
            popupContent,
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
            true
        )

        // Show the popup centered on the anchor view
        popupWindow.showAtLocation(anchorView, Gravity.CENTER, 0, 0)
    }

}