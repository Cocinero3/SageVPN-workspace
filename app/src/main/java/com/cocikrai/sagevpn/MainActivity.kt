package com.cocikrai.sagevpn

import android.annotation.SuppressLint
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {

    private lateinit var btStartVPN:Button

    @SuppressLint("UnsafeIntentLaunch")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        btStartVPN = findViewById(R.id.btStart)

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