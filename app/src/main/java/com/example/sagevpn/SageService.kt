package com.example.sagevpn

import android.content.Intent
import android.net.VpnService
import android.util.Log

class SageService:VpnService() {

    private var mThread: Thread? = null
    private var mInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("SAGE", "onStart has been triggered for Sage")
        mThread = Thread({
            try {
                runVpn()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }, "MyVpnThread")
        mThread?.start()
        return START_STICKY
    }

    override fun onDestroy() {
        mThread?.interrupt()
        try {
            mInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        super.onDestroy()
    }

    private fun runVpn() {
        try {
            prepare(this)
            val builder = Builder()
            mInterface = builder.setSession("MyVpnService")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .establish()

            val inputStream = FileInputStream(mInterface?.fileDescriptor)
            val buffer = ByteArray(32767)
            // VPN processing loop
            while (true) {
                val length = inputStream.read(buffer)
                if(length > 0) {
                    val packetInfo = buffer.take(10).joinToString(":") { "%02x".format(it) }
                    Log.d("VPN", "Received packet: $packetInfo")
                }

            }
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            mInterface?.close()
        }
    }

    companion object {
        val ACTION_CONNECT: String = "com.example.android.myapplication.START"
    }
}