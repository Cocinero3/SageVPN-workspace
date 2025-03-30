package com.cocikrai.sagevpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.lifecycle.MutableLiveData
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
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
        Log.d("SAGE", "onDestroy has been triggered for Sage")
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

                val data = Packet(stream)
                packetLiveData.postValue(data)
                buffer.rewind()

                if(data.ipv4Headers != null) {
                    try {
                        val socket = DatagramSocket()
                        val payload = ByteArray(buffer.remaining())
                        buffer.get(payload)
                        val address = InetAddress.getByAddress(data.ipv4Headers!!.desIPArray)
                        val packet = DatagramPacket(payload,payload.size, address, data.destPort)
                        protect(socket)
                        socket.send(packet)

                        socket.close()
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }

                }

                buffer.rewind()
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
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            mInterface?.close()
        }
    }

    companion object {
        val packetLiveData: MutableLiveData<Packet> = MutableLiveData()
        val ACTION_CONNECT: String = "com.example.android.myapplication.START"
    }
}