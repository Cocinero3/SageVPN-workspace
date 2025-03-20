package com.cocikrai.sagevpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.nio.ByteBuffer



class SageService : VpnService() {

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
            val buffer: ByteBuffer = ByteBuffer.allocate(32767)
            // VPN processing loop
            while (true) {
                val length = inputStream.read(buffer.array())
                val stream: ByteBuffer = buffer

                val versionAndHeaderLength: Byte = stream.get()
                val ipVersion = (versionAndHeaderLength.toInt() shr 4).toByte()
                if (ipVersion.toInt() != 0x04) {
                    buffer.clear()
                } else {
                    val internetHeaderLength = (versionAndHeaderLength.toInt() and 0x0F).toByte()
                    if (stream.capacity() < internetHeaderLength * 4) {
                        throw Exception("Not enough space in array for IP header")
                    }

                    val dscpAndEcn: Byte = stream.get()
                    val dscp = (dscpAndEcn.toInt() shr 2).toByte()
                    val ecn = (dscpAndEcn.toInt() and 0x03).toByte()
                    val totalLength: Short = stream.getShort()
                    val identification: Short = stream.getShort()
                    val flagsAndFragmentOffset: Short = stream.getShort()
                    val mayFragment = (flagsAndFragmentOffset.toInt() and 0x4000) != 0
                    val lastFragment = (flagsAndFragmentOffset.toInt() and 0x2000) != 0
                    val fragmentOffset = (flagsAndFragmentOffset.toInt() and 0x1FFF).toShort()
                    val timeToLive: Byte = stream.get()
                    val protocol: Byte = stream.get()
                    val checksum: Short = stream.getShort()
                    val sourceIPArray = ByteArray(4)
                    sourceIPArray[0] = stream.get()
                    sourceIPArray[1] = stream.get()
                    sourceIPArray[2] = stream.get()
                    sourceIPArray[3] = stream.get()
                    //val sourceIp: Int = stream.getInt()
                    //val desIp: Int = stream.getInt()
                    val desIPArray = ByteArray(4)
                    desIPArray[0] = stream.get()
                    desIPArray[1] = stream.get()
                    desIPArray[2] = stream.get()
                    desIPArray[3] = stream.get()
                    Log.i("SAGEVPN-sourceIP", sourceIPArray.joinToString(".") { "%02X".format(it) })
                    Log.i("SAGEVPN-desIP", desIPArray.joinToString(".") { "%02X".format(it) })

                    if(length > 0) {
                        Log.i("SAGEVPN","************new packet");
                        var runningString: String = ""
                        while (buffer.hasRemaining()) {
                            val bufferValue = buffer.get()
                            runningString += String.format("%02X", bufferValue)
                            //Log.i("SAGEVPN",""+ bufferValue.toString());
                        }

                        Log.i("SAGEVPN", runningString)
                        buffer.clear();
                        //val packetInfo = buffer.take(50).joinToString(":") { "%02s".format(it) }
                        //Log.d("VPN", "Received packet: $packetInfo")
                    }
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