package com.cocikrai.sagevpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.lifecycle.MutableLiveData
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.Selector
import java.nio.channels.SelectionKey
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.net.Socket
import java.nio.channels.SocketChannel
import kotlin.concurrent.thread
import java.util.concurrent.atomic.AtomicInteger
import kotlin.experimental.and

private data class TcpConnectionState(
    val connectionKey: String,
    var localSeqNum: Long = 1000L,
    var remoteSeqNum: Long = 0L,
    var remoteWindowSize: Int = 65535,
    var lastAckSent: Long = 0L,
    var windowSize: Int = 65535,
    var established: Boolean = false,
    var sentSyn: Boolean = false
)

private data class ConnectionEndpoints(
    val ip1: String,
    val port1: Int,
    val ip2: String,
    val port2: Int
) {
    // Generate a normalized key that's the same regardless of direction
    fun toNormalizedKey(): String {
        // Sort the endpoints lexicographically to ensure a consistent key
        return if (ip1 < ip2 || (ip1 == ip2 && port1 < port2)) {
            "$ip1:$port1-$ip2:$port2"
        } else {
            "$ip2:$port2-$ip1:$port1"
        }
    }

    // Get the directional key in the format "$sourceIp:$sourcePort-$destIp:$destPort"
    fun toDirectionalKey(sourceIp: String, sourcePort: Int): String {
        return if (sourceIp == ip1 && sourcePort == port1) {
            "$ip1:$port1-$ip2:$port2"
        } else {
            "$ip2:$port2-$ip1:$port1"
        }
    }

    // Create a companion object to parse and create ConnectionEndpoints
    companion object {
        fun fromConnectionKey(key: String): ConnectionEndpoints {
            val parts = key.split("-")
            if (parts.size != 2) throw IllegalArgumentException("Invalid connection key format: $key")

            val sourceParts = parts[0].split(":")
            val destParts = parts[1].split(":")

            // Handle IPv6 addresses which contain multiple colons
            val isSourceIpv6 = sourceParts.size > 2
            val isDestIpv6 = destParts.size > 2

            val sourceIp: String
            val sourcePort: Int
            val destIp: String
            val destPort: Int

            if (isSourceIpv6) {
                // For IPv6, the last part is the port
                sourcePort = sourceParts.last().toInt()
                // And the address is everything else
                sourceIp = sourceParts.dropLast(1).joinToString(":")
            } else {
                // Standard IPv4 handling
                sourceIp = sourceParts[0]
                sourcePort = sourceParts[1].toInt()
            }

            if (isDestIpv6) {
                // For IPv6, the last part is the port
                destPort = destParts.last().toInt()
                // And the address is everything else
                destIp = destParts.dropLast(1).joinToString(":")
            } else {
                // Standard IPv4 handling
                destIp = destParts[0]
                destPort = destParts[1].toInt()
            }

            return ConnectionEndpoints(sourceIp, sourcePort, destIp, destPort)
        }

        fun create(sourceIp: String, sourcePort: Int, destIp: String, destPort: Int): ConnectionEndpoints {
            return ConnectionEndpoints(sourceIp, sourcePort, destIp, destPort)
        }
    }
}

class SageService : VpnService() {
    private var running = AtomicBoolean(true)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private val executorService = Executors.newCachedThreadPool()

    private var blacklistIps: ArrayList<String> = ArrayList()
    private var isStarted = false

    private val tcpConnections = ConcurrentHashMap<String, SocketChannel>() // Key is normalized connection key
    private val tcpConnectionDirections = ConcurrentHashMap<String, String>() // Maps normalized key to directional key
    private val udpConnections = ConcurrentHashMap<String, DatagramChannel>() // Key is normalized connection key
    private val udpConnectionDirections = ConcurrentHashMap<String, String>() // Maps normalized key to directional key

    private val selector = Selector.open()

    private val tcpConnectionStates = ConcurrentHashMap<String, TcpConnectionState>()

    companion object {
        val packetLiveData: MutableLiveData<Packet> = MutableLiveData()
        const val TAG = "SageVPN"
        private const val BUFFER_SIZE = 32767

        // Debug flags
        const val DEBUG_PACKET_DETAILS = false     // Log detailed packet info
        const val DEBUG_FORWARDING = false         // Log packet forwarding
        const val DEBUG_CONNECTIONS = false        // Log connection establishment

        private val PORT_SERVICES = mapOf(
            53 to "DNS",
            80 to "HTTP",
            443 to "HTTPS/QUIC",
            853 to "DNS-over-TLS"
        )

        // Track packet counts for statistics
        private val packetCounts = ConcurrentHashMap<String, AtomicInteger>()
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if(!isStarted) {
            Log.d(TAG, "Starting SageVPN Service")

            // Start VPN in a background thread
            vpnThread = Thread({
                try {
                    establishVpn()
                } catch (e: Exception) {
                    Log.e(TAG, "VPN thread error", e)
                }
            }, "SageVpnThread")
            vpnThread?.start()
        } else {
            val blockIp = intent?.getStringExtra("block")
            if(blockIp == "stop") {
                stopVpn()
                super.onDestroy()
            } else {
                blacklistIps.add(blockIp!!)
            }
        }


        return START_STICKY
    }

    override fun onRevoke() {
        Log.d(TAG, "VPN service revoked")
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.d(TAG, "VPN service destroyed")
        stopVpn()
        super.onDestroy()
    }

    private fun stopVpn() {
        isStarted = false
        running.set(false)

        try {
            // Close all TCP connections
            for ((key, channel) in tcpConnections) {
                try {
                    val directionKey = tcpConnectionDirections[key] ?: key
                    if (DEBUG_CONNECTIONS) Log.d(TAG, "Closing TCP connection: $directionKey")
                    channel.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing TCP connection: $key", e)
                }
            }
            tcpConnections.clear()
            tcpConnectionDirections.clear()

            // Close all UDP connections
            for ((key, channel) in udpConnections) {
                try {
                    val directionKey = udpConnectionDirections[key] ?: key
                    if (DEBUG_CONNECTIONS) Log.d(TAG, "Closing UDP connection: $directionKey")
                    channel.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing UDP connection: $key", e)
                }
            }
            udpConnections.clear()
            udpConnectionDirections.clear()

            // Close selector
            try {
                selector.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing selector", e)
            }

            // Shutdown executor service
            executorService.shutdown()

            // Close VPN interface
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping VPN", e)
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun establishVpn() {
        try {
            // Set up VPN interface
            val builder = Builder()
                .setSession("SageVPN")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addRoute("0.0.0.0", 0)  // Route all IPv4 traffic
                .setMtu(BUFFER_SIZE)
                .allowFamily(android.system.OsConstants.AF_INET)  // Allow IPv4

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN connection")
                return
            }

            Log.d(TAG, "VPN interface established")

            // Start network I/O handler thread
            val responseThread = Thread({
                handleNetworkResponses()
            }, "NetworkResponseThread")
            responseThread.start()

            // Process VPN traffic
            processVpnTraffic()

        } catch (e: Exception) {
            Log.e(TAG, "VPN establishment error: ${e.message}", e)
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun processVpnTraffic() {
        var inStream: FileInputStream? = null
        var outStream: FileOutputStream? = null

        try {
            inStream = FileInputStream(vpnInterface!!.fileDescriptor)
            outStream = FileOutputStream(vpnInterface!!.fileDescriptor)

            val packet = ByteBuffer.allocate(BUFFER_SIZE)

            while (running.get()) {
                // Clear buffer for new data
                packet.clear()

                // Read packet from VPN interface
                val length = inStream.read(packet.array())
                if (length <= 0) {
                    Thread.sleep(10)
                    continue
                }

                // Set buffer limit to actual read length
                packet.limit(length)

                // Process the packet
                val packetCopy = ByteBuffer.allocate(length)
                System.arraycopy(packet.array(), 0, packetCopy.array(), 0, length)

                // Analyze and forward packet (non-blocking)
                executorService.execute {
                    try {
                        val packetInfo = Packet(packetCopy.duplicate())
                        packetLiveData.postValue(packetInfo)

                        if (DEBUG_PACKET_DETAILS) {
                            logPacketInfo(packetInfo)
                        }

                        // Forward packet to its destination if not in the blacklist
                        if(!blacklistIps.contains(packetInfo.destIpString)) {
                            forwardPacket(packetInfo, packetCopy)
                        }

                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing packet", e)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in VPN traffic processing: ${e.message}", e)
        } finally {
            try {
                inStream?.close()
                outStream?.close()
            } catch (e: Exception) {
                Log.e(TAG, "Error closing streams", e)
            }
        }
    }

    private fun formatIp(bytes: ByteArray): String {
        return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun forwardPacket(packet: Packet, rawData: ByteBuffer) {
        try {
            if (packet.ipVersion.toInt() == 4) {
                // Handle IPv4 packet
                val ipv4 = packet.ipv4Headers ?: return
                val srcIp = formatIp(ipv4.sourceIPArray)
                val dstIp = formatIp(ipv4.desIPArray)
                val protocol = ipv4.protocol.toInt() and 0xFF

                when (protocol) {
                    6 -> { // TCP
                        val sourcePort = packet.sourcePort
                        val destPort = packet.destPort

                        // Log detailed packet info
                        logDetailedPacketInfo(packet, "TCP", srcIp, dstIp, sourcePort, destPort)

                        // Handle the packet
                        handleTcpPacket(srcIp, dstIp, sourcePort, destPort, rawData)
                    }
                    17 -> { // UDP
                        val sourcePort = packet.sourcePort
                        val destPort = packet.destPort

                        // Log DNS packets
                        if (destPort == 53 || sourcePort == 53) {
                            Log.d(TAG, "DNS over UDP: $srcIp:$sourcePort -> $dstIp:$destPort")
                        }

                        // Log detailed packet info
                        logDetailedPacketInfo(packet, "UDP", srcIp, dstIp, sourcePort, destPort)

                        // Handle the packet
                        handleUdpPacket(srcIp, dstIp, sourcePort, destPort, rawData)
                    }
                    1 -> { // ICMP
                        // Log detailed packet info (ICMP doesn't use ports)
                        logDetailedPacketInfo(packet, "ICMP", srcIp, dstIp, 0, 0)

                        // Handle the packet
                        handleIcmpPacket(srcIp, dstIp, rawData)
                    }
                    else -> {
                        if (DEBUG_FORWARDING) {
                            Log.d(TAG, "Unsupported IPv4 protocol: $protocol from $srcIp to $dstIp")
                        }
                    }
                }
            } else if (packet.ipVersion.toInt() == 6) {
                // Handle IPv6 packet
                val ipv6 = packet.ipv6Headers ?: return
                val srcIp = ipv6.getSourceString()
                val dstIp = ipv6.getDestinationString()
                val nextHeader = ipv6.nextHeader.toInt() and 0xFF

                when (nextHeader) {
                    6 -> { // TCP
                        val sourcePort = packet.sourcePort
                        val destPort = packet.destPort

                        // Log detailed packet info
                        logDetailedPacketInfo(packet, "TCP-IPv6", srcIp, dstIp, sourcePort, destPort)

                        // Handle the packet
                        handleTcpPacketIpv6(srcIp, dstIp, sourcePort, destPort, rawData)
                    }
                    17 -> { // UDP
                        val sourcePort = packet.sourcePort
                        val destPort = packet.destPort

                        // Log DNS packets
                        if (destPort == 53 || sourcePort == 53) {
                            Log.d(TAG, "DNS over UDP (IPv6): $srcIp:$sourcePort -> $dstIp:$destPort")
                        }

                        // Log detailed packet info
                        logDetailedPacketInfo(packet, "UDP-IPv6", srcIp, dstIp, sourcePort, destPort)

                        // Handle the packet
                        handleUdpPacketIpv6(srcIp, dstIp, sourcePort, destPort, rawData)
                    }
                    else -> {
                        if (DEBUG_FORWARDING) {
                            Log.d(TAG, "Unsupported IPv6 next header: $nextHeader from $srcIp to $dstIp")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Enhanced error logging with packet details
            Log.e(TAG, "Error forwarding packet: ${e.message}", e)
            try {
                val srcIp = if (packet.ipVersion.toInt() == 4) {
                    formatIp(packet.ipv4Headers?.sourceIPArray ?: ByteArray(4))
                } else {
                    packet.ipv6Headers?.getSourceString() ?: "unknown"
                }

                val dstIp = if (packet.ipVersion.toInt() == 4) {
                    formatIp(packet.ipv4Headers?.desIPArray ?: ByteArray(4))
                } else {
                    packet.ipv6Headers?.getDestinationString() ?: "unknown"
                }

                Log.e(TAG, "Packet details: srcIP=$srcIp, dstIP=$dstIp, " +
                        "srcPort=${packet.sourcePort}, dstPort=${packet.destPort}, " +
                        "version=${packet.ipVersion}")
            } catch (detailsError: Exception) {
                Log.e(TAG, "Couldn't even get packet details: ${detailsError.message}")
            }
        }
    }


    private fun handleTcpPacket(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val endpoints = ConnectionEndpoints.create(sourceIp, sourcePort, destIp, destPort)
        val normalizedKey = endpoints.toNormalizedKey()
        val directionalKey = endpoints.toDirectionalKey(sourceIp, sourcePort)

        try {
            // Get or create TCP connection using the normalized key
            var channel = tcpConnections[normalizedKey]

            if (channel == null || !channel.isConnected) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new TCP connection: $directionalKey (normalized: $normalizedKey)")

                // Create new TCP connection
                channel = SocketChannel.open()

                // Protect this socket from VPN
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect TCP socket: $directionalKey")
                    throw IOException("Failed to protect socket from VPN loopback")
                } else {
                    Log.d(TAG, "TCP socket protected from VPN: $directionalKey (localPort=${channel.socket().localPort})")
                }

                channel.configureBlocking(false)

                // Connect to destination
                val destAddress = InetSocketAddress(destIp, destPort)
                channel.connect(destAddress)

                // Register with selector for non-blocking I/O
                channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ, normalizedKey)

                // Store the connection with normalized key
                tcpConnections[normalizedKey] = channel
                // Store the directional key for this connection
                tcpConnectionDirections[normalizedKey] = directionalKey

                // Create TCP connection state
                val stateKey = "$sourceIp:$sourcePort-$destIp:$destPort"
                val connectionState = TcpConnectionState(stateKey)

                // Extract TCP flags and sequence numbers from packet
                extractTcpInfo(data, connectionState)

                tcpConnectionStates[stateKey] = connectionState

                if (DEBUG_FORWARDING) Log.d(TAG, "TCP connection pending: $directionalKey")
            }

            // If the channel is connected, write data
            if (channel!!.isConnected) {
                // Extract payload from IP packet
                data.position(0)
                val packetObj = Packet(data.duplicate())
                val headerSize = (packetObj.ipv4Headers?.internetHeaderLength?.toInt() ?: 5) * 4
                val packetData = data.duplicate()

                // Update TCP state based on packet content
                val stateKey = "$sourceIp:$sourcePort-$destIp:$destPort"
                val connectionState = tcpConnectionStates[stateKey] ?: TcpConnectionState(stateKey)
                extractTcpInfo(packetData, connectionState)
                tcpConnectionStates[stateKey] = connectionState

                // Position buffer to skip IP header
                data.position(headerSize)

                // Write data to channel
                val bytesWritten = channel.write(data)

                if (DEBUG_FORWARDING) Log.d(TAG, "TCP forwarded $bytesWritten bytes to $destIp:$destPort " +
                        "(SEQ=${connectionState.remoteSeqNum}, ACK=${connectionState.localSeqNum})")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling TCP packet: ${e.message}", e)

            // Close and remove the failed connection
            try {
                tcpConnections.remove(normalizedKey)?.close()
                tcpConnectionDirections.remove(normalizedKey)
            } catch (closeEx: Exception) {
                Log.e(TAG, "Error closing TCP connection", closeEx)
            }
        }
    }

    // New method to extract TCP information from packets
    private fun extractTcpInfo(data: ByteBuffer, state: TcpConnectionState) {
        try {
            // Create a duplicate to avoid modifying the original position
            val buffer = data.duplicate()
            buffer.position(0)

            // Parse IP header first
            val packetObj = Packet(buffer.duplicate())
            val ipHeaderLength = (packetObj.ipv4Headers?.internetHeaderLength?.toInt() ?: 5) * 4

            // Position for TCP header
            buffer.position(ipHeaderLength)

            // Extract TCP header values
            val sourcePort = ((buffer.get().toLong() and 0xFF) shl 8) or (buffer.get().toLong() and 0xFF)
            val destPort = ((buffer.get().toLong() and 0xFF) shl 8) or (buffer.get().toLong() and 0xFF)

            // Sequence number (4 bytes)
            val seqNum = ((buffer.get().toLong() and 0xFF) shl 24) or
                    ((buffer.get().toLong() and 0xFF) shl 16) or
                    ((buffer.get().toLong() and 0xFF) shl 8) or
                    (buffer.get().toLong() and 0xFF)

            // Acknowledgment number (4 bytes)
            val ackNum = ((buffer.get().toLong() and 0xFF) shl 24) or
                    ((buffer.get().toLong() and 0xFF) shl 16) or
                    ((buffer.get().toLong() and 0xFF) shl 8) or
                    (buffer.get().toLong() and 0xFF)

            // Data offset and flags
            val dataOffset = (buffer.get().toInt() and 0xF0) shr 4
            val flags = buffer.get().toInt() and 0xFF

            // Window size (2 bytes)
            val windowSize = ((buffer.get().toInt() and 0xFF) shl 8) or (buffer.get().toInt() and 0xFF)

            // Update connection state
            if ((flags and 0x02) != 0) {  // SYN flag
                state.remoteSeqNum = seqNum + 1  // SYN consumes one sequence number
                state.sentSyn = true
            } else if ((flags and 0x01) != 0) {  // FIN flag
                state.remoteSeqNum = seqNum + 1  // FIN consumes one sequence number
            } else {
                // Calculate payload size
                val ipTotalLength = packetObj.ipv4Headers?.totalLength?.toInt() ?: 0
                val tcpHeaderLength = dataOffset * 4
                val payloadSize = ipTotalLength - ipHeaderLength - tcpHeaderLength

                if (payloadSize > 0) {
                    state.remoteSeqNum = seqNum + payloadSize
                } else {
                    state.remoteSeqNum = seqNum
                }
            }

            if ((flags and 0x10) != 0) {  // ACK flag
                state.localSeqNum = ackNum
            }

            state.remoteWindowSize = windowSize

            if ((flags and 0x12) == 0x12) {  // SYN+ACK
                state.established = true
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting TCP info: ${e.message}", e)
        }
    }

    // Modified UDP connection methods
    private fun handleUdpPacket(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val endpoints = ConnectionEndpoints.create(sourceIp, sourcePort, destIp, destPort)
        val normalizedKey = endpoints.toNormalizedKey()
        val directionalKey = endpoints.toDirectionalKey(sourceIp, sourcePort)

        try {
            // Get or create UDP connection using the normalized key
            var channel = udpConnections[normalizedKey]

            if (channel == null) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new UDP connection: $directionalKey (normalized: $normalizedKey)")

                // Create new UDP connection
                channel = DatagramChannel.open()

                // Protect this socket from VPN
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect UDP socket: $directionalKey")
                    throw IOException("Failed to protect socket from VPN loopback")
                } else {
                    Log.d(TAG, "UDP socket protected from VPN: $directionalKey (localPort=${channel.socket().localPort})")
                }

                channel.configureBlocking(false)

                // Connect to destination
                val destAddress = InetSocketAddress(destIp, destPort)
                channel.connect(destAddress)

                // Register with selector for non-blocking I/O
                channel.register(selector, SelectionKey.OP_READ, normalizedKey)

                // Store the connection with normalized key
                udpConnections[normalizedKey] = channel
                // Store the directional key for this connection
                udpConnectionDirections[normalizedKey] = directionalKey

                if (DEBUG_FORWARDING) Log.d(TAG, "UDP connection created: $directionalKey")
            }

            // Extract payload from IP packet
            channel?.let { safeChannel ->
                data.position(0)
                val packetObj = Packet(data.duplicate())
                val headerSize = (packetObj.ipv4Headers?.internetHeaderLength?.toInt() ?: 5) * 4

                // Skip IP header and UDP header (8 bytes)
                data.position(headerSize + 8)

                // Get payload data
                val payloadSize = data.remaining()
                val payload = ByteArray(payloadSize)
                data.get(payload)

                // Create datagram packet
                val packet = ByteBuffer.wrap(payload)

                // Send the packet
                val bytesSent = channel.write(packet)

                if (DEBUG_FORWARDING) Log.d(TAG, "UDP forwarded $bytesSent bytes to $destIp:$destPort")
            } ?: run {
                Log.e(TAG, "Failed to create UDP connection for $directionalKey")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling UDP packet: ${e.message}", e)

            // Close and remove the failed connection
            udpConnections.remove(normalizedKey)?.close()
            udpConnectionDirections.remove(normalizedKey)
        }
    }

    // Modified TCP IPv6 connection method
    private fun handleTcpPacketIpv6(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val endpoints = ConnectionEndpoints.create(sourceIp, sourcePort, destIp, destPort)
        val normalizedKey = endpoints.toNormalizedKey()
        val directionalKey = endpoints.toDirectionalKey(sourceIp, sourcePort)

        try {
            // Get or create TCP connection using the normalized key
            var channel = tcpConnections[normalizedKey]

            if (channel == null || !channel.isConnected) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new IPv6 TCP connection: $directionalKey (normalized: $normalizedKey)")

                // Create new TCP connection
                channel = SocketChannel.open()

                // IMPORTANT: Protect the socket first, before any other operations
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect IPv6 TCP socket: $directionalKey")
                    throw IOException("Failed to protect IPv6 socket from VPN loopback")
                } else {
                    Log.d(TAG, "IPv6 TCP socket protected from VPN: $directionalKey")
                }

                // Now configure the socket
                channel.configureBlocking(false)

                // Convert string IPv6 address to InetAddress
                try {
                    // Clean up the IPv6 address if it ends with a colon (as seen in logs)
                    val cleanDestIp = if (destIp.endsWith(":")) destIp.substring(0, destIp.length - 1) else destIp
                    val destAddress = InetSocketAddress(InetAddress.getByName(cleanDestIp), destPort)

                    Log.d(TAG, "Connecting IPv6 TCP to: $cleanDestIp:$destPort")
                    channel.connect(destAddress)

                    // Register with selector for non-blocking I/O
                    channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ, normalizedKey)

                    // Store the connection with normalized key
                    tcpConnections[normalizedKey] = channel
                    // Store the directional key for this connection
                    tcpConnectionDirections[normalizedKey] = directionalKey

                    if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 TCP connection pending: $directionalKey")
                } catch (e: Exception) {
                    Log.e(TAG, "IPv6 address parsing error: ${e.message}", e)
                    throw e
                }
            }

            // If the channel is connected, write data
            if (channel?.isConnected == true) {
                // Extract payload from IPv6 packet
                data.position(0)
                val packetObj = Packet(data.duplicate())

                // IPv6 has a 40-byte fixed header, followed by optional extension headers
                // We need to find the TCP header start position
                val ipv6Headers = packetObj.ipv6Headers ?: throw IOException("Invalid IPv6 headers")

                // Skip IPv6 header (40 bytes) and any extension headers if present
                // For simplicity in this implementation, assuming no extension headers
                data.position(40)

                // Write data to channel
                val bytesWritten = channel?.write(data)

                if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 TCP forwarded $bytesWritten bytes to $destIp:$destPort")
            } else {
                if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 TCP connection not yet established: $directionalKey")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling IPv6 TCP packet: ${e.message}", e)

            // Close and remove the failed connection
            try {
                tcpConnections.remove(normalizedKey)?.close()
                tcpConnectionDirections.remove(normalizedKey)
            } catch (closeEx: Exception) {
                Log.e(TAG, "Error closing IPv6 TCP connection", closeEx)
            }
        }
    }

    // Modified UDP IPv6 connection method
    private fun handleUdpPacketIpv6(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val endpoints = ConnectionEndpoints.create(sourceIp, sourcePort, destIp, destPort)
        val normalizedKey = endpoints.toNormalizedKey()
        val directionalKey = endpoints.toDirectionalKey(sourceIp, sourcePort)

        try {
            // Get or create UDP connection using the normalized key
            var channel = udpConnections[normalizedKey]

            if (channel == null) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new IPv6 UDP connection: $directionalKey (normalized: $normalizedKey)")

                // Create new UDP connection
                channel = DatagramChannel.open()

                // IMPORTANT: Protect the socket first, before any other operations
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect IPv6 UDP socket: $directionalKey")
                    throw IOException("Failed to protect IPv6 socket from VPN loopback")
                } else {
                    Log.d(TAG, "IPv6 UDP socket protected from VPN: $directionalKey")
                }

                // Now configure the socket
                channel.configureBlocking(false)

                // Bind to a local address to ensure we have a specific port
                channel.socket().bind(InetSocketAddress(0))
                Log.d(TAG, "IPv6 UDP socket bound to local port: ${channel.socket().localPort}")

                // Convert string IPv6 address to InetAddress
                try {
                    // Clean up the IPv6 address if it ends with a colon (as seen in logs)
                    val cleanDestIp = if (destIp.endsWith(":")) destIp.substring(0, destIp.length - 1) else destIp
                    val destAddress = InetSocketAddress(InetAddress.getByName(cleanDestIp), destPort)

                    Log.d(TAG, "Connecting IPv6 UDP to: $cleanDestIp:$destPort")
                    channel.connect(destAddress)

                    // Register with selector for non-blocking I/O
                    channel.register(selector, SelectionKey.OP_READ, normalizedKey)

                    // Store the connection with normalized key
                    udpConnections[normalizedKey] = channel
                    // Store the directional key for this connection
                    udpConnectionDirections[normalizedKey] = directionalKey

                    if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 UDP connection created: $directionalKey")
                } catch (e: Exception) {
                    Log.e(TAG, "IPv6 address parsing error: ${e.message}", e)
                    throw e
                }
            }

            // Extract payload from IPv6 packet
            data.position(0)
            val packetObj = Packet(data.duplicate())

            // Skip IPv6 header (40 bytes fixed) and UDP header (8 bytes)
            data.position(40 + 8)

            // Get payload data
            val payloadSize = data.remaining()
            val payload = ByteArray(payloadSize)
            data.get(payload)

            // Create datagram packet
            val packet = ByteBuffer.wrap(payload)

            // Send the packet
            val bytesSent = channel?.write(packet)

            if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 UDP forwarded $bytesSent bytes to $destIp:$destPort")
        } catch (e: Exception) {
            Log.e(TAG, "Error handling IPv6 UDP packet: ${e.message}", e)

            // Close and remove the failed connection
            try {
                udpConnections.remove(normalizedKey)?.close()
                udpConnectionDirections.remove(normalizedKey)
            } catch (closeEx: Exception) {
                Log.e(TAG, "Error closing IPv6 UDP connection", closeEx)
            }
        }
    }

    private fun handleIcmpPacket(sourceIp: String, destIp: String, data: ByteBuffer) {
        // ICMP handling is more complex - for debugging we'll just log it
        if (DEBUG_FORWARDING) Log.d(TAG, "ICMP packet from $sourceIp to $destIp")

        // For a complete implementation, we would need to:
        // 1. Extract the ICMP packet from the IP packet
        // 2. Create a raw socket (requires root on Android)
        // 3. Send the ICMP packet to the destination
        // 4. Handle ICMP responses
    }

    private fun handleNetworkResponses() {
        try {
            val outStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            val buffer = ByteBuffer.allocate(BUFFER_SIZE)

            while (running.get()) {
                // Check for activity on registered channels
                val readyChannels = selector.select(100)
                if (readyChannels == 0) continue

                // Process ready keys
                val keys = selector.selectedKeys()
                val iterator = keys.iterator()

                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()

                    try {
                        if (key.isConnectable) {
                            handleConnectable(key)
                        }

                        if (key.isReadable) {
                            // Read from network and write to VPN
                            handleReadable(key, buffer, outStream)
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error handling channel: ${e.message}", e)
                        key.cancel()

                        // Close the channel
                        try {
                            key.channel().close()
                        } catch (e: Exception) {
                            Log.e(TAG, "Error closing channel", e)
                        }

                        // Remove from connection maps
                        val connectionKey = key.attachment() as? String
                        if (connectionKey != null) {
                            tcpConnections.remove(connectionKey)
                            udpConnections.remove(connectionKey)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in network response handling: ${e.message}", e)
        }
    }

    private fun handleConnectable(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val normalizedKey = key.attachment() as? String ?: "unknown"

        // Complete connection
        if (channel.isConnectionPending) {
            try {
                val connected = channel.finishConnect()

                if (connected) {
                    // Get the directional key for logging
                    val directionalKey = tcpConnectionDirections[normalizedKey] ?: normalizedKey

                    // Extract destination info from directional key
                    val endpoints = ConnectionEndpoints.fromConnectionKey(directionalKey)
                    Log.d(TAG, "Connection to ${endpoints.ip2}:${endpoints.port2} established successfully")

                    if (DEBUG_CONNECTIONS) {
                        Log.d(TAG, "TCP connection established: $directionalKey (normalized: $normalizedKey)")
                    }

                    // Update interest to read
                    key.interestOps(SelectionKey.OP_READ)
                } else {
                    val directionalKey = tcpConnectionDirections[normalizedKey] ?: normalizedKey
                    Log.e(TAG, "Failed to establish connection: $directionalKey")
                    key.cancel()
                    channel.close()

                    // Remove from connections map
                    tcpConnections.remove(normalizedKey)
                    tcpConnectionDirections.remove(normalizedKey)
                }
            } catch (e: Exception) {
                val directionalKey = tcpConnectionDirections[normalizedKey] ?: normalizedKey
                Log.e(TAG, "Error finishing connection: ${e.message}")
                key.cancel()
                channel.close()
                tcpConnections.remove(normalizedKey)
                tcpConnectionDirections.remove(normalizedKey)
            }
        }
    }

    // Modify handleReadable method to work with normalized keys
    private fun handleReadable(key: SelectionKey, buffer: ByteBuffer, outStream: FileOutputStream) {
        val normalizedKey = key.attachment() as String

        // Get the directional key that was originally stored
        val directionKey = if (key.channel() is SocketChannel) {
            tcpConnectionDirections[normalizedKey] ?: normalizedKey
        } else {
            udpConnectionDirections[normalizedKey] ?: normalizedKey
        }

        // Parse the connection endpoints
        val endpoints = ConnectionEndpoints.fromConnectionKey(directionKey)

        // For responses, we swap the source and destination
        val sourceIp = endpoints.ip2
        val destIp = endpoints.ip1
        val sourcePort = endpoints.port2
        val destPort = endpoints.port1

        // Determine if this is IPv6
        val isIpv6 = sourceIp.contains(":")

        // Clear buffer for new data
        buffer.clear()

        try {
            if (key.channel() is SocketChannel) {
                // TCP channel
                val channel = key.channel() as SocketChannel

                try {
                    val bytesRead = channel.read(buffer)

                    if (bytesRead <= 0) {
                        // Connection closed or error
                        if (bytesRead < 0) {
                            if (DEBUG_CONNECTIONS) Log.d(TAG, "TCP connection closed: $directionKey (normalized: $normalizedKey)")
                            channel.close()
                            key.cancel()
                            tcpConnections.remove(normalizedKey)
                            tcpConnectionDirections.remove(normalizedKey)

                            // Also remove state entry
                            val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                            tcpConnectionStates.remove(reversedKey)
                        }
                        return
                    }

                    if (DEBUG_FORWARDING) {
                        Log.d(TAG, "TCP received $bytesRead bytes from $sourceIp:$sourcePort")
                    }

                    // Prepare buffer for sending
                    buffer.flip()

                    // Get the TCP connection state for proper sequence tracking
                    val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                    val connectionState = tcpConnectionStates[reversedKey] ?: TcpConnectionState(reversedKey)

                    // Update sequence numbers for response
                    connectionState.localSeqNum += bytesRead

                    // Store updated state
                    tcpConnectionStates[reversedKey] = connectionState

                    // Create and send response packet based on IP version
                    if (isIpv6) {
                        createAndSendTcpPacketIpv6(sourceIp, destIp, sourcePort, destPort, buffer, bytesRead, outStream, connectionState)
                        Log.d(TAG, "IPv6 TCP response delivered to app: $destIp:$destPort ($bytesRead bytes)")
                    } else {
                        createAndSendTcpPacket(sourceIp, destIp, sourcePort, destPort, buffer, bytesRead, outStream, connectionState)
                        Log.d(TAG, "IPv4 TCP response delivered to app: $destIp:$destPort ($bytesRead bytes)")
                    }
                } catch (e: IOException) {
                    // Handle connection reset specifically with better logging
                    if (e.message?.contains("Connection reset") == true) {
                        Log.e(TAG, "TCP connection was reset by peer: $directionKey", e)
                    } else {
                        Log.e(TAG, "Error reading from TCP channel: ${e.message}", e)
                    }

                    // Clean up the connection
                    try {
                        channel.close()
                        key.cancel()
                        tcpConnections.remove(normalizedKey)
                        tcpConnectionDirections.remove(normalizedKey)

                        // Also remove state entry
                        val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                        tcpConnectionStates.remove(reversedKey)
                    } catch (closeEx: Exception) {
                        Log.e(TAG, "Error closing TCP connection after reset", closeEx)
                    }
                }
            } else if (key.channel() is DatagramChannel) {
                // UDP channel - this remains unchanged
                val channel = key.channel() as DatagramChannel
                val bytesRead = channel.read(buffer)

                if (bytesRead <= 0) return

                if (DEBUG_FORWARDING) {
                    Log.d(TAG, "UDP received $bytesRead bytes from $sourceIp:$sourcePort")
                }

                // Prepare buffer for sending
                buffer.flip()

                // Create and send response packet based on IP version
                if (isIpv6) {
                    createAndSendUdpPacketIpv6(sourceIp, destIp, sourcePort, destPort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv6 UDP response delivered to app: $destIp:$destPort ($bytesRead bytes)")
                } else {
                    createAndSendUdpPacket(sourceIp, destIp, sourcePort, destPort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv4 UDP response delivered to app: $destIp:$destPort ($bytesRead bytes)")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling readable channel: ${e.message}", e)
            try {
                key.cancel()
                key.channel().close()

                if (key.channel() is SocketChannel) {
                    tcpConnections.remove(normalizedKey)
                    tcpConnectionDirections.remove(normalizedKey)

                    // Also remove state entry
                    val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                    tcpConnectionStates.remove(reversedKey)
                } else if (key.channel() is DatagramChannel) {
                    udpConnections.remove(normalizedKey)
                    udpConnectionDirections.remove(normalizedKey)
                }
            } catch (closeErr: Exception) {
                Log.e(TAG, "Error cleaning up channel resources", closeErr)
            }
        }
    }

    private fun createAndSendTcpPacket(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream,
        connectionState: TcpConnectionState
    ) {
        try {
            // Extract payload data
            val payloadData = ByteArray(payloadSize)
            payload.get(payloadData)

            // 1. Create IP header (20 bytes)
            val ipHeader = ByteBuffer.allocate(20)
            ipHeader.put(0, (4 shl 4 or 5).toByte())  // Version 4, Header Length 5 (20 bytes)
            ipHeader.put(1, 0)  // ToS
            val totalLength = 20 + 20 + payloadSize  // IP + TCP + Payload
            ipHeader.putShort(2, totalLength.toShort())
            ipHeader.putShort(4, (Math.random() * 65535).toInt().toShort())  // ID
            ipHeader.putShort(6, 0x4000.toShort())  // Don't Fragment
            ipHeader.put(8, 64)  // TTL
            ipHeader.put(9, 6)  // Protocol (TCP)
            ipHeader.putShort(10, 0)  // Checksum (calculated later)

            // Source IP
            val srcIpParts = sourceIp.split(".")
            for (i in 0..3) {
                ipHeader.put(12 + i, srcIpParts[i].toInt().toByte())
            }

            // Destination IP
            val dstIpParts = destIp.split(".")
            for (i in 0..3) {
                ipHeader.put(16 + i, dstIpParts[i].toInt().toByte())
            }

            // 2. Create TCP header (20 bytes)
            val tcpHeader = ByteBuffer.allocate(20)
            tcpHeader.putShort(0, sourcePort.toShort())
            tcpHeader.putShort(2, destPort.toShort())

            // Sequence number - use tracked sequence number
            tcpHeader.putInt(4, connectionState.localSeqNum.toInt())

            // ACK number - acknowledge data received
            tcpHeader.putInt(8, connectionState.remoteSeqNum.toInt())

            // Data offset and flags - always include ACK flag for responses
            tcpHeader.put(12, (5 shl 4).toByte())  // Header length 5 words (20 bytes)

            // For responses, we use both ACK (0x10) and PSH (0x08) flags
            tcpHeader.put(13, 0x18.toByte())  // PSH and ACK flags

            // Window size - use value from state
            tcpHeader.putShort(14, connectionState.windowSize.toShort())

            // Checksum and urgent pointer
            tcpHeader.putShort(16, 0)  // Checksum (calculated later)
            tcpHeader.putShort(18, 0)  // Urgent pointer

            // 3. Calculate checksums - use more robust checksum calculation
            // TCP checksum requires a pseudo-header
            val pseudoHeader = ByteBuffer.allocate(12)
            // Source IP
            for (i in 0..3) {
                pseudoHeader.put(i, ipHeader.get(12 + i))
            }
            // Destination IP
            for (i in 0..3) {
                pseudoHeader.put(4 + i, ipHeader.get(16 + i))
            }
            pseudoHeader.put(8, 0)  // Zero
            pseudoHeader.put(9, 6)  // Protocol
            pseudoHeader.putShort(10, (20 + payloadSize).toShort())  // TCP length

            // Calculate TCP checksum
            val tcpChecksum = calculateChecksum(pseudoHeader.array(), tcpHeader.array(), payloadData)
            tcpHeader.putShort(16, tcpChecksum)

            // Calculate IP checksum
            val ipChecksum = calculateIPChecksum(ipHeader.array())
            ipHeader.putShort(10, ipChecksum)

            // 4. Build and send the complete packet
            val packet = ByteBuffer.allocate(totalLength)
            ipHeader.position(0)
            tcpHeader.position(0)

            packet.put(ipHeader)
            packet.put(tcpHeader)
            packet.put(payloadData)

            outStream.write(packet.array(), 0, totalLength)

            if (DEBUG_FORWARDING) {
                Log.d(TAG, "TCP response sent: $sourceIp:$sourcePort -> $destIp:$destPort " +
                        "(SEQ=${connectionState.localSeqNum}, ACK=${connectionState.remoteSeqNum})")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating TCP packet: ${e.message}", e)
        }
    }

    // Helper methods for checksums
    private fun calculateChecksum(vararg arrays: ByteArray): Short {
        var sum = 0L
        var odd = false

        for (array in arrays) {
            var i = 0
            while (i < array.size) {
                if (odd) {
                    sum += (array[i].toInt() and 0xFF)
                    i++
                    odd = false
                } else if (i == array.size - 1) {
                    sum += ((array[i].toInt() and 0xFF) shl 8)
                    i++
                    odd = true
                } else {
                    sum += (((array[i].toInt() and 0xFF) shl 8) or (array[i + 1].toInt() and 0xFF))
                    i += 2
                }

                // Add carries
                while (sum > 0xFFFF) {
                    sum = (sum and 0xFFFF) + (sum shr 16)
                }
            }
        }

        // Take one's complement
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun calculateIPChecksum(ipHeader: ByteArray): Short {
        var sum = 0

        // Process header as 16-bit words
        for (i in 0 until 20 step 2) {
            // Skip checksum field
            if (i == 10) continue

            val word = ((ipHeader[i].toInt() and 0xFF) shl 8) or (ipHeader[i + 1].toInt() and 0xFF)
            sum += word

            // Add carries
            if (sum > 0xFFFF) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
        }

        // Take one's complement
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun createAndSendUdpPacket(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream
    ) {
        try {
            // Extract payload data
            val payloadData = ByteArray(payloadSize)
            payload.get(payloadData)

            // 1. Create IP header (20 bytes)
            val ipHeader = ByteBuffer.allocate(20)
            ipHeader.put(0, (4 shl 4 or 5).toByte())  // Version 4, Header Length 5 (20 bytes)
            ipHeader.put(1, 0)  // ToS
            val totalLength = 20 + 8 + payloadSize  // IP + UDP + Payload
            ipHeader.putShort(2, totalLength.toShort())
            ipHeader.putShort(4, (Math.random() * 65535).toInt().toShort())  // ID
            ipHeader.putShort(6, 0x4000.toShort())  // Don't Fragment
            ipHeader.put(8, 64)  // TTL
            ipHeader.put(9, 17)  // Protocol (UDP)
            ipHeader.putShort(10, 0)  // Checksum (calculated later)

            // Source IP
            val srcIpParts = sourceIp.split(".")
            for (i in 0..3) {
                ipHeader.put(12 + i, srcIpParts[i].toInt().toByte())
            }

            // Destination IP
            val dstIpParts = destIp.split(".")
            for (i in 0..3) {
                ipHeader.put(16 + i, dstIpParts[i].toInt().toByte())
            }

            // 2. Create UDP header (8 bytes)
            val udpHeader = ByteBuffer.allocate(8)
            udpHeader.putShort(0, sourcePort.toShort())
            udpHeader.putShort(2, destPort.toShort())
            udpHeader.putShort(4, (8 + payloadSize).toShort())  // Length
            udpHeader.putShort(6, 0)  // Checksum (optional for IPv4)

            // 3. Calculate checksums
            // UDP checksum is optional for IPv4, but recommended

            // Calculate IP checksum
            val ipChecksum = calculateIPChecksum(ipHeader.array())
            ipHeader.putShort(10, ipChecksum)

            // 4. Build and send the complete packet
            val packet = ByteBuffer.allocate(totalLength)
            ipHeader.position(0)
            udpHeader.position(0)

            packet.put(ipHeader)
            packet.put(udpHeader)
            packet.put(payloadData)

            outStream.write(packet.array(), 0, totalLength)

            if (DEBUG_FORWARDING) {
                Log.d(TAG, "UDP response sent: $sourceIp:$sourcePort -> $destIp:$destPort ($payloadSize bytes)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating UDP packet: ${e.message}", e)
        }
    }

    private fun createAndSendTcpPacketIpv6(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream,
        connectionState: TcpConnectionState
    ) {
        try {
            // IPv6 header (40 bytes fixed)
            val ipv6Header = ByteBuffer.allocate(40)

            // Version & Traffic Class & Flow Label
            ipv6Header.putInt(0, 0x60000000)  // Version 6, Traffic Class 0, Flow Label 0

            // Payload Length (TCP header + data)
            ipv6Header.putShort(4, (20 + payloadSize).toShort())

            // Next Header (TCP = 6)
            ipv6Header.put(6, 6)

            // Hop Limit (like TTL)
            ipv6Header.put(7, 64)

            // Source IPv6 Address (16 bytes)
            putIpv6Address(ipv6Header, 8, sourceIp)

            // Destination IPv6 Address (16 bytes)
            putIpv6Address(ipv6Header, 24, destIp)

            // TCP Header (20 bytes minimal, no options)
            val tcpHeader = ByteBuffer.allocate(20)
            tcpHeader.putShort(0, sourcePort.toShort())
            tcpHeader.putShort(2, destPort.toShort())

            // Sequence number - use tracked sequence number
            tcpHeader.putInt(4, connectionState.localSeqNum.toInt())

            // ACK number - acknowledge all data received
            tcpHeader.putInt(8, connectionState.remoteSeqNum.toInt())

            // Data offset and flags
            tcpHeader.put(12, (5 shl 4).toByte())  // 5 words (20 bytes), no reserved bits
            tcpHeader.put(13, 0x18.toByte())  // PSH + ACK flags

            // Window size - use state value
            tcpHeader.putShort(14, connectionState.windowSize.toShort())

            // Checksum and urgent pointer
            tcpHeader.putShort(16, 0)  // Checksum
            tcpHeader.putShort(18, 0)  // Urgent pointer

            // Extract payload data
            val payloadData = ByteArray(payloadSize)
            payload.get(payloadData)

            // Combine everything
            val totalSize = ipv6Header.capacity() + tcpHeader.capacity() + payloadSize
            val fullPacket = ByteBuffer.allocate(totalSize)

            ipv6Header.flip()
            tcpHeader.flip()

            fullPacket.put(ipv6Header)
            fullPacket.put(tcpHeader)
            fullPacket.put(payloadData)

            // Write to VPN
            outStream.write(fullPacket.array(), 0, totalSize)

            if (DEBUG_FORWARDING) {
                Log.d(TAG, "IPv6 TCP response sent: $sourceIp:$sourcePort -> $destIp:$destPort (${payloadSize} bytes)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating IPv6 TCP packet: ${e.message}", e)
        }
    }

    private fun createAndSendUdpPacketIpv6(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream
    ) {
        try {
            // IPv6 header (40 bytes fixed)
            val ipv6Header = ByteBuffer.allocate(40)

            // Version & Traffic Class & Flow Label
            ipv6Header.putInt(0, 0x60000000)  // Version 6, Traffic Class 0, Flow Label 0

            // Payload Length (UDP header + data)
            ipv6Header.putShort(4, (8 + payloadSize).toShort())

            // Next Header (UDP = 17)
            ipv6Header.put(6, 17)

            // Hop Limit (like TTL)
            ipv6Header.put(7, 64)

            // Source IPv6 Address (16 bytes)
            putIpv6Address(ipv6Header, 8, sourceIp)

            // Destination IPv6 Address (16 bytes)
            putIpv6Address(ipv6Header, 24, destIp)

            // UDP Header (8 bytes)
            val udpHeader = ByteBuffer.allocate(8)
            udpHeader.putShort(0, sourcePort.toShort())
            udpHeader.putShort(2, destPort.toShort())
            udpHeader.putShort(4, (8 + payloadSize).toShort())  // Length
            udpHeader.putShort(6, 0)  // Checksum (optional for IPv6 with no extension headers)

            // Extract payload data
            val payloadData = ByteArray(payloadSize)
            payload.get(payloadData)

            // Combine everything
            val totalSize = ipv6Header.capacity() + udpHeader.capacity() + payloadSize
            val fullPacket = ByteBuffer.allocate(totalSize)

            ipv6Header.flip()
            udpHeader.flip()

            fullPacket.put(ipv6Header)
            fullPacket.put(udpHeader)
            fullPacket.put(payloadData)

            // Write to VPN
            outStream.write(fullPacket.array(), 0, totalSize)

            if (DEBUG_FORWARDING) {
                Log.d(TAG, "IPv6 UDP response sent: $sourceIp:$sourcePort -> $destIp:$destPort (${payloadSize} bytes)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating IPv6 UDP packet: ${e.message}", e)
        }
    }

    // Helper method to parse and set IPv6 addresses
    private fun putIpv6Address(buffer: ByteBuffer, offset: Int, address: String) {
        try {
            // Clean up the address if it ends with a colon
            val cleanAddress = if (address.endsWith(":"))
                address.substring(0, address.length - 1)
            else
                address

            // Parse the IPv6 address
            val ipv6Address = InetAddress.getByName(cleanAddress)
            val addressBytes = ipv6Address.address

            // Put the bytes in the buffer
            for (i in addressBytes.indices) {
                buffer.put(offset + i, addressBytes[i])
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing IPv6 address: $address", e)
            // Fill with zeros in case of error
            for (i in 0 until 16) {
                buffer.put(offset + i, 0)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun logDetailedPacketInfo(packet: Packet, protocol: String, sourceIp: String, destIp: String, sourcePort: Int, destPort: Int) {
        try {
            val sourcePort = packet.sourcePort
            val destPort = packet.destPort

            // Determine service if known
            val service = PORT_SERVICES[destPort] ?: "unknown"

            // Create a key for statistics
            val statsKey = "$protocol:$service:$destIp:$destPort"

            // Update packet count
            val count = packetCounts.computeIfAbsent(statsKey) { AtomicInteger(0) }
            val packetNum = count.incrementAndGet()

            // Log detailed info for important packets
            if (service != "unknown" || packetNum % 100 == 1) {  // Log every 100th packet for unknown services
                Log.d(TAG, "PACKET[$packetNum]: $protocol to $service ($destIp:$destPort) from $sourceIp:$sourcePort")

                // Extra logging for DNS to debug name resolution
                if (service == "DNS" || service == "DNS-over-TLS") {
                    Log.d(TAG, "  DNS request detected - checking if it's handled properly")
                }

                // Log Google services specifically
                if (destIp.contains("google") || destIp.startsWith("172.217.") ||
                    destIp.startsWith("64.233.") || destIp.startsWith("216.58.")) {
                    Log.d(TAG, "  Google service detected: $statsKey")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in detailed packet logging", e)
        }
    }
    private fun logPacketInfo(packet: Packet) {
        try {
            if (packet.ipVersion.toInt() == 4) {
                // IPv4 packet
                val ipv4 = packet.ipv4Headers ?: return
                val srcIp = formatIp(ipv4.sourceIPArray)
                val dstIp = formatIp(ipv4.desIPArray)
                val protocol = ipv4.protocol.toInt() and 0xFF

                when (protocol) {
                    6 -> { // TCP
                        Log.d(TAG, "IPv4 TCP Packet: $srcIp:${packet.sourcePort} -> $dstIp:${packet.destPort}")
                    }
                    17 -> { // UDP
                        Log.d(TAG, "IPv4 UDP Packet: $srcIp:${packet.sourcePort} -> $dstIp:${packet.destPort}")
                    }
                    1 -> { // ICMP
                        Log.d(TAG, "IPv4 ICMP Packet: $srcIp -> $dstIp")
                    }
                    else -> {
                        Log.d(TAG, "IPv4 Packet (protocol $protocol): $srcIp -> $dstIp")
                    }
                }
            } else if (packet.ipVersion.toInt() == 6) {
                // IPv6 packet
                val ipv6 = packet.ipv6Headers ?: return
                Log.d(TAG, "IPv6 Packet: ${ipv6.getSourceString()} -> ${ipv6.getDestinationString()} (Next Header: ${ipv6.nextHeader})")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error logging packet: ${e.message}")
        }
    }
}
