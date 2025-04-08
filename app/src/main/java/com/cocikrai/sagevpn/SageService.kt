package com.cocikrai.sagevpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.lifecycle.MutableLiveData
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel


class SageService : VpnService() {

    private var mThread: Thread? = null
    private var mInterface: ParcelFileDescriptor? = null
    private var isStarted = false

    private var blacklistIps: ArrayList<String> = ArrayList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        if(!isStarted) {
            isStarted = true
            Log.d("SAGE", "onStart has been triggered for Sage")
            mThread = Thread({
                try {
                    runVpn()
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }, "MyVpnThread")
            mThread?.start()
        } else {
            val blockIp = intent?.getStringExtra("block")
            if(blockIp == "stop") {
                stopForeground(true)
                Log.d("SAGE", "onDestroy has been triggered for Sage")
                mThread?.interrupt()
                try {
                    mInterface?.close()
                } catch (e: Exception) {
                    e.printStackTrace()
                }
                super.onDestroy()
            } else {
                blacklistIps.add(blockIp!!)
            }
        }

        return START_STICKY
    }

    override fun onRevoke() {
        Log.d("SAGE", "onRevoke has been triggered for Sage")
        stopForeground(true)
        mThread?.interrupt()
        try {
            mInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        stopForeground(true)
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
                .setMtu(1500)
                .establish()

            val inputStream = FileInputStream(mInterface?.fileDescriptor)
            val outputStream = FileOutputStream(mInterface?.fileDescriptor)



            val buffer: ByteBuffer = ByteBuffer.allocate(32767)
            // VPN processing loop
            while (true) {
                val length = inputStream.read(buffer.array())
                if(length > 0) {
                    val stream: ByteBuffer = buffer
                    stream.limit(length)
                    val data = Packet(stream)
                    packetLiveData.postValue(data)
                    buffer.rewind()



                    if (data.ipv4Headers != null && !blacklistIps.contains(
                            data.ipv4Headers!!.desIPArray.joinToString(
                                "."
                            ) { "%d".format(it.toInt() and 0xFF) })
                    ) {
                        try {
//                        val socket = Socket()
//                        socket.bind(InetSocketAddress(0))
//                        val payload = ByteArray(buffer.remaining())
//                        buffer.get(payload)
//                        val address = InetAddress.getByAddress(data.ipv4Headers!!.desIPArray)
//                        Log.i("SAGEVPN-Socket", address.toString())
//                        val packet = DatagramPacket(data.backBuffer,data.backBuffer.size, address, data.destPort)
//                        protect(socket)
//
//                        socket.connect(InetSocketAddress(address, data.destPort))
//                        Log.i("SAGEVPN-SOCKET", socket.isConnected.toString())
//                        socket.getOutputStream().write(data.backBuffer)
//
//                        val responsePacket = ByteBuffer.allocate(65535)
//                        val socketInputStream = socket.getInputStream()
//                        try {
//                            val responseLength = socketInputStream.read(responsePacket.array())
//                            if (responseLength > 20) {
//
//                                val trimmedResponseData = ByteBuffer.allocate(responseLength)
//                                System.arraycopy(
//                                    responsePacket.array(),
//                                    0,
//                                    trimmedResponseData.array(),
//                                    0,
//                                    responseLength
//                                )
//
//                                val finalPacket = ByteBuffer.allocate(40 + responseLength)
//                                val swappedIpHeader = swapSrcDstAddress(getIpHeader(buffer)[0])
//                                buffer.rewind()
//                                val swappedTcpHeader = if(data.ipv4Headers!!.protocol.toInt() == 0x06)
//                                    swapTCPSrcDst(getTCPHeader(getIpHeader(buffer)[1])[0]) else swapTCPSrcDst(getUDPHeader(getIpHeader(buffer)[1])[0])
//
//                                finalPacket.put(swappedIpHeader.array())
//                                finalPacket.put(swappedTcpHeader.array())
//                                finalPacket.put(trimmedResponseData.array())
//                                Log.i("SAGEVPN-FINAL", finalPacket.array().joinToString(" ") { "%02X".format(it) })
//                                outputStream.write(finalPacket.array())
//                            }
//                        } catch (e: java.lang.Exception) {
//                            e.printStackTrace()
//                        }

//                        socket.close()
//                        val address = InetAddress.getByAddress(data.ipv4Headers!!.desIPArray)
//                        val tunnel = DatagramChannel.open()
//                        protect(tunnel.socket())
//
//                        tunnel.connect(InetSocketAddress(address, data.destPort))
//                        tunnel.configureBlocking(false)
//
//                        buffer.limit(length)
//                        tunnel.write(buffer)
//                        buffer.clear()
//                        val tunnelLength = tunnel.read(buffer)
//
//                        if(tunnelLength > 0) {
//                            if(buffer.get(0) != 0.toByte()) {
//                                outputStream.write(buffer.array(), 0, tunnelLength)
//                            }
//                            buffer.clear()
//                        }
//                        tunnel.close()


                        } catch (e: Exception) {
                            e.printStackTrace()
                        }

                    }
                }
              buffer.rewind()
                if(length > 0) {
                    Log.i("SAGEVPN","************new packet");
                    val fullPacket = ByteArray(buffer.remaining())
                    buffer.get(fullPacket)
                    var runningString: String = fullPacket.joinToString(" ") { "%02X".format(it) }

                    Log.i("SAGEVPN", runningString)
                    buffer.clear();

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