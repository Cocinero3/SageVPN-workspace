package com.cocikrai.sagevpn

import android.util.Log
import java.nio.ByteBuffer
import kotlin.experimental.and

fun readUnsignedShort(buffer: ByteBuffer): Int {
    return (buffer.get().toInt() and 0xFF) shl 8 or (buffer.get().toInt() and 0xFF)
}

class IPV4Headers(stream: ByteBuffer, version: Byte, ihl: Byte) {

    var ipVersion = version
    var internetHeaderLength = ihl
    var dscpAndEcn: Byte = 0
    var dscp: Byte = 0x00
    var ecn: Byte = 0x00
    var totalLength: Short = 0
    var identification: Short = 0
    var flagsAndFragmentOffset: Short = 0
    var mayFragment = false
    var lastFragment = false
    var fragmentOffset: Short = 0
    var timeToLive: Byte = 0x00
    var protocol: Byte = 0x00
    var checksum: Short = 0
    val sourceIPArray = ByteArray(4)
    val desIPArray = ByteArray(4)

    init {
        if (stream.capacity() < internetHeaderLength * 4) {
            throw Exception("Not enough space in array for IP header")
        }

        dscpAndEcn = stream.get()
        dscp = (dscpAndEcn.toInt() shr 2).toByte()
        ecn = (dscpAndEcn.toInt() and 0x03).toByte()
        totalLength = stream.getShort()
        identification = stream.getShort()
        flagsAndFragmentOffset = stream.getShort()
        mayFragment = (flagsAndFragmentOffset.toInt() and 0x4000) != 0
        lastFragment = (flagsAndFragmentOffset.toInt() and 0x2000) != 0
        fragmentOffset = (flagsAndFragmentOffset.toInt() and 0x1FFF).toShort()
        timeToLive = stream.get()
        protocol = stream.get()
        checksum = stream.getShort()
        stream.get(sourceIPArray)
        stream.get(desIPArray)

        Log.i("SAGEVPN-sourceIP", sourceIPArray.joinToString(".") { "%d".format(it.toInt() and 0xFF) })
        Log.i("SAGEVPN-desIP", desIPArray.joinToString(".") { "%d".format(it.toInt() and 0xFF) })
        Log.i("SAGEVPN-ip4-protocol", String.format("%02X", protocol))
    }
}

class IPV6Headers(stream: ByteBuffer, version: Byte, extra: Byte) {

    var ipVersion = version
    var priority = extra
    var flowLabel = ByteArray(3)
    init {
        stream.get(flowLabel)
    }
    var payloadLength = stream.getShort()
    var nextHeader = stream.get()
    var hopLimits = stream.get()
    var sourceIP = ByteArray(16)
    var destinationIP = ByteArray(16)
    init {
        stream.get(sourceIP)
        stream.get(destinationIP)
        var sourceString = ""
        var destinationString = ""
        for(i in 0..14 step 2) {
            sourceString += String.format("%02X", sourceIP[i]) + String.format("%02X", sourceIP[i+1]) + ":"
            destinationString += String.format("%02X", destinationIP[i]) + String.format("%02X", destinationIP[i+1]) + ":"
        }
        Log.i("SAGEVPN-sourceIP-RAW", sourceIP.joinToString(":") { "%02X".format(it) })
        Log.i("SAGEVPN-desIP-RAW", destinationIP.joinToString(":") { "%02X".format(it) })
        Log.i("SAGEVPN-sourceIP-string", sourceString)
        Log.i("SAGEVPN-desIP-string", destinationString)
        Log.i("SAGEVPN-nextHeader", String.format("%02X", nextHeader))

        var remaining = ByteArray(stream.remaining())
        stream.get(remaining)

        Log.i("SAGEVPN-REMAINING", remaining.joinToString("") { "%02X".format(it) })
    }

    fun getSourceString(): String {
        var sourceString = ""
        for(i in 0..14 step 2) {
            sourceString += String.format("%02X", sourceIP[i]) + String.format("%02X", sourceIP[i+1]) + ":"
        }
        return sourceString.dropLast(1)
    }

    fun getDestinationString(): String {
        var destinationString = ""
        for(i in 0..14 step 2) {
            destinationString += String.format("%02X", destinationIP[i]) + String.format("%02X", destinationIP[i+1]) + ":"
        }

        return destinationString.dropLast(1)
    }
}


class Packet(stream: ByteBuffer) {

    val versionAndHeaderLength: Byte = stream.get()
    val ipVersion = (versionAndHeaderLength.toInt() shr 4).toByte()
    val internetHeaderLength = (versionAndHeaderLength.toInt() and 0x0F).toByte()

    var ipv4Headers: IPV4Headers? = null
    var ipv6Headers: IPV6Headers? = null

    var sourcePort: Int = 0
    var destPort: Int = 0

    init {
        if (ipVersion.toInt() != 0x04) {
            ipv6Headers = IPV6Headers(stream, ipVersion, internetHeaderLength)
        } else {
            ipv4Headers = IPV4Headers(stream, ipVersion, internetHeaderLength)
            sourcePort = readUnsignedShort(stream)
            destPort = readUnsignedShort(stream)
            Log.i("SAGEVPN-sourcePort", sourcePort.toString())
            Log.i("SAGEVPN-destPort", destPort.toString())


        }
    }
    val backBuffer = stream

}