package com.example.sagevpn

import android.content.Intent
import android.net.VpnService
import android.util.Log

class SageService:VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("SAGE", "onStart has been triggered for Sage")
        return START_STICKY
        //return super.onStartCommand(intent, flags, startId)
    }

    companion object {
        val ACTION_CONNECT: String = "com.example.android.myapplication.START"
    }
}