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

private data class TcpConnectionState(
    val connectionKey: String,
    var localSeqNum: Long = (Math.random() * 1000000).toLong(),  // More random initial sequence number
    var remoteSeqNum: Long = 0L,    // Last sequence number received
    var lastAckSent: Long = 0L,     // Last ACK we sent
    var windowSize: Int = 65535,    // TCP window size
    var state: TcpState = TcpState.CLOSED,
    var retries: Int = 0
)

enum class TcpState {
    CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK
}

class SageService : VpnService() {
    private val TCP_MAX_RETRIES = 3
    private val TCP_RETRY_TIMEOUT_MS = 2000L
    private var running = AtomicBoolean(true)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private val executorService = Executors.newCachedThreadPool()

    private var blacklistIps: ArrayList<String> = ArrayList()
    private var isStarted = false

    private val tcpConnections = ConcurrentHashMap<String, SocketChannel>()
    private val udpConnections = ConcurrentHashMap<String, DatagramChannel>()

    private val selector = Selector.open()

    private val tcpConnectionStates = ConcurrentHashMap<String, TcpConnectionState>()

    companion object {
        val packetLiveData: MutableLiveData<Packet> = MutableLiveData()
        const val TAG = "SageVPN"
        private const val BUFFER_SIZE = 32767

        // Debug flags
        const val DEBUG_PACKET_DETAILS = true     // Log detailed packet info
        const val DEBUG_FORWARDING = true         // Log packet forwarding
        const val DEBUG_CONNECTIONS = true        // Log connection establishment

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
                    if (DEBUG_CONNECTIONS) Log.d(TAG, "Closing TCP connection: $key")
                    channel.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing TCP connection: $key", e)
                }
            }
            tcpConnections.clear()

            // Close all UDP connections
            for ((key, channel) in udpConnections) {
                try {
                    if (DEBUG_CONNECTIONS) Log.d(TAG, "Closing UDP connection: $key")
                    channel.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing UDP connection: $key", e)
                }
            }
            udpConnections.clear()

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
        val connectionKey = "$sourceIp:$sourcePort-$destIp:$destPort"

        try {
            // Get or create TCP connection
            var channel = tcpConnections[connectionKey]

            if (channel == null || !channel.isConnected) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new TCP connection: $connectionKey")

                // Create TCP state for the connection first
                val stateKey = "$sourceIp:$sourcePort-$destIp:$destPort"
                var connectionState = tcpConnectionStates[stateKey]
                if (connectionState == null) {
                    connectionState = TcpConnectionState(stateKey)
                    connectionState.state = TcpState.SYN_SENT
                    tcpConnectionStates[stateKey] = connectionState
                }

                // Create new TCP connection
                channel = SocketChannel.open()

                // Protect this socket from VPN
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect TCP socket: $connectionKey")
                    throw IOException("Failed to protect socket from VPN loopback")
                } else {
                    Log.d(TAG, "TCP socket protected from VPN: $connectionKey (localPort=${channel.socket().localPort})")
                }

                channel.configureBlocking(false)

                // Connect to destination
                val destAddress = InetSocketAddress(destIp, destPort)
                val connectStarted = channel.connect(destAddress)

                if (connectStarted) {
                    // Connection completed immediately
                    connectionState.state = TcpState.ESTABLISHED
                    if (DEBUG_FORWARDING) Log.d(TAG, "TCP connection established immediately: $connectionKey")
                } else {
                    // Connection pending
                    if (DEBUG_FORWARDING) Log.d(TAG, "TCP connection pending: $connectionKey")
                }

                // Register with selector for non-blocking I/O
                channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ, connectionKey)

                // Store the connection
                tcpConnections[connectionKey] = channel
            }

            // Extract TCP flags and update connection state
            val packet = Packet(data.duplicate())
            val ipHeaderLen = (packet.ipv4Headers?.internetHeaderLength?.toInt() ?: 5) * 4
            val tcpHeaderOffset = ipHeaderLen

            // Read TCP flags
            if (data.capacity() >= tcpHeaderOffset + 13) {
                data.position(tcpHeaderOffset + 13)
                val flags = data.get().toInt() and 0xFF

                // TCP flags processing
                val isSyn = (flags and 0x02) != 0
                val isAck = (flags and 0x10) != 0
                val isRst = (flags and 0x04) != 0
                val isFin = (flags and 0x01) != 0

                // Get connection state
                val stateKey = "$sourceIp:$sourcePort-$destIp:$destPort"
                val connectionState = tcpConnectionStates[stateKey]

                if (isRst) {
                    // Handle RST - close connection
                    if (DEBUG_CONNECTIONS) Log.d(TAG, "TCP RST received, closing: $connectionKey")
                    channel?.close()
                    tcpConnections.remove(connectionKey)
                    tcpConnectionStates.remove(stateKey)
                    return
                }

                if (isFin) {
                    // Handle FIN - acknowledge it
                    if (connectionState != null) {
                        connectionState.state = TcpState.FIN_WAIT
                        if (DEBUG_CONNECTIONS) Log.d(TAG, "TCP FIN received, sending ACK: $connectionKey")
                    }
                }
            }

            // If the channel is connected, write data
            if (channel != null && channel.isConnected) {
                // Extract payload from IP packet - with correct offsets
                data.position(0)
                val packetObj = Packet(data.duplicate())
                val ipHeaderLen = (packetObj.ipv4Headers?.internetHeaderLength?.toInt() ?: 5) * 4

                // Get TCP header length
                data.position(ipHeaderLen + 12)
                val dataOffset = (data.get().toInt() and 0xF0) shr 4
                val tcpHeaderLen = dataOffset * 4

                // Position buffer to skip IP header and TCP header
                data.position(ipHeaderLen + tcpHeaderLen)

                // Only write if there's data to send (not just TCP control packets)
                if (data.hasRemaining()) {
                    val bytesWritten = channel.write(data)
                    if (DEBUG_FORWARDING) Log.d(TAG, "TCP forwarded $bytesWritten bytes to $destIp:$destPort")
                } else if (DEBUG_FORWARDING) {
                    Log.d(TAG, "TCP control packet (no data payload) to $destIp:$destPort")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling TCP packet: ${e.message}", e)

            // Close and remove the failed connection with retries
            val stateKey = "$sourceIp:$sourcePort-$destIp:$destPort"
            val connectionState = tcpConnectionStates[stateKey]

            if (connectionState != null && connectionState.retries < TCP_MAX_RETRIES) {
                connectionState.retries++
                Log.d(TAG, "TCP connection retry ${connectionState.retries}/$TCP_MAX_RETRIES for $connectionKey")

                // Schedule retry if appropriate
                if (e is IOException && e.message?.contains("reset") == true) {
                    // Don't retry on connection reset
                    tcpConnections.remove(connectionKey)?.close()
                    tcpConnectionStates.remove(stateKey)
                }
            } else {
                // Max retries reached or no state - close connection
                tcpConnections.remove(connectionKey)?.close()
                tcpConnectionStates.remove(stateKey)
            }
        }
    }

    private fun handleUdpPacket(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val connectionKey = "$sourceIp:$sourcePort-$destIp:$destPort"

        try {
            // Get or create UDP connection
            var channel = udpConnections[connectionKey]

            if (channel == null) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new UDP connection: $connectionKey")

                // Create new UDP connection
                channel = DatagramChannel.open()

                // Protect this socket from VPN
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect UDP socket: $connectionKey")
                    throw IOException("Failed to protect socket from VPN loopback")
                } else {
                    Log.d(TAG, "UDP socket protected from VPN: $connectionKey (localPort=${channel.socket().localPort})")
                }

                channel.configureBlocking(false)

                // Connect to destination
                val destAddress = InetSocketAddress(destIp, destPort)
                channel.connect(destAddress)

                // Register with selector for non-blocking I/O
                channel.register(selector, SelectionKey.OP_READ, connectionKey)

                // Store the connection
                udpConnections[connectionKey] = channel

                if (DEBUG_FORWARDING) Log.d(TAG, "UDP connection created: $connectionKey")
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
                Log.e(TAG, "Failed to create UDP connection for $connectionKey")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling UDP packet: ${e.message}", e)

            // Close and remove the failed connection
            udpConnections.remove(connectionKey)?.close()
        }
    }

    private fun handleTcpPacketIpv6(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val connectionKey = "$sourceIp:$sourcePort-$destIp:$destPort"

        try {
            // Get or create TCP connection
            var channel = tcpConnections[connectionKey]

            if (channel == null || !channel.isConnected) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new IPv6 TCP connection: $connectionKey")

                // Create new TCP connection
                channel = SocketChannel.open()

                // IMPORTANT: Protect the socket first, before any other operations
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect IPv6 TCP socket: $connectionKey")
                    throw IOException("Failed to protect IPv6 socket from VPN loopback")
                } else {
                    Log.d(TAG, "IPv6 TCP socket protected from VPN: $connectionKey")
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
                    channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ, connectionKey)

                    // Store the connection
                    tcpConnections[connectionKey] = channel

                    if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 TCP connection pending: $connectionKey")
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
                if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 TCP connection not yet established: $connectionKey")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling IPv6 TCP packet: ${e.message}", e)

            // Close and remove the failed connection
            try {
                tcpConnections.remove(connectionKey)?.close()
            } catch (closeEx: Exception) {
                Log.e(TAG, "Error closing IPv6 TCP connection", closeEx)
            }
        }
    }

    private fun handleUdpPacketIpv6(sourceIp: String, destIp: String, sourcePort: Int, destPort: Int, data: ByteBuffer) {
        val connectionKey = "$sourceIp:$sourcePort-$destIp:$destPort"

        try {
            // Get or create UDP connection
            var channel = udpConnections[connectionKey]

            if (channel == null) {
                if (DEBUG_CONNECTIONS) Log.d(TAG, "Creating new IPv6 UDP connection: $connectionKey")

                // Create new UDP connection
                channel = DatagramChannel.open()

                // IMPORTANT: Protect the socket first, before any other operations
                val socketProtected = protect(channel.socket())
                if (!socketProtected) {
                    Log.e(TAG, "ERROR: Failed to protect IPv6 UDP socket: $connectionKey")
                    throw IOException("Failed to protect IPv6 socket from VPN loopback")
                } else {
                    Log.d(TAG, "IPv6 UDP socket protected from VPN: $connectionKey")
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
                    channel.register(selector, SelectionKey.OP_READ, connectionKey)

                    // Store the connection
                    udpConnections[connectionKey] = channel

                    if (DEBUG_FORWARDING) Log.d(TAG, "IPv6 UDP connection created: $connectionKey")
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
                udpConnections.remove(connectionKey)?.close()
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
        val connectionKey = key.attachment() as? String ?: "unknown"

        // Complete connection
        if (channel.isConnectionPending) {
            try {
                val connected = channel.finishConnect()

                if (connected) {
                    // Extract destination info from connectionKey
                    val parts = connectionKey.split("-")
                    if (parts.size == 2) {
                        val destParts = parts[1].split(":")
                        if (destParts.size == 2) {
                            val destIp = destParts[0]
                            val destPort = destParts[1]
                            Log.d(TAG, "Connection to $destIp:$destPort established successfully")
                        }
                    }

                    // Update connection state
                    val connectionState = tcpConnectionStates[connectionKey]
                    if (connectionState != null) {
                        connectionState.state = TcpState.ESTABLISHED
                        connectionState.retries = 0  // Reset retries on successful connection
                    }

                    if (DEBUG_CONNECTIONS) {
                        Log.d(TAG, "TCP connection established: $connectionKey")
                    }

                    // Update interest to read
                    key.interestOps(SelectionKey.OP_READ)
                } else {
                    Log.e(TAG, "Failed to establish connection: $connectionKey")

                    // Check for retries
                    val connectionState = tcpConnectionStates[connectionKey]
                    if (connectionState != null && connectionState.retries < TCP_MAX_RETRIES) {
                        // Retry
                        connectionState.retries++
                        Log.d(TAG, "Retrying connection ($connectionKey): ${connectionState.retries}/$TCP_MAX_RETRIES")

                        // Keep the key, just update interests
                        key.interestOps(SelectionKey.OP_CONNECT)
                    } else {
                        // Give up
                        key.cancel()
                        channel.close()
                        tcpConnections.remove(connectionKey)
                        tcpConnectionStates.remove(connectionKey)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error finishing connection: ${e.message}", e)

                // Check for retries
                val connectionState = tcpConnectionStates[connectionKey]
                if (connectionState != null && connectionState.retries < TCP_MAX_RETRIES) {
                    // Retry
                    connectionState.retries++
                    Log.d(TAG, "Connection error, retrying ($connectionKey): ${connectionState.retries}/$TCP_MAX_RETRIES")

                    try {
                        // Close existing channel
                        channel.close()
                        key.cancel()

                        // Extract connection details
                        val parts = connectionKey.split("-")
                        val sourceParts = parts[0].split(":")
                        val destParts = parts[1].split(":")

                        if (parts.size == 2 && sourceParts.size >= 2 && destParts.size >= 2) {
                            val sourceIp = sourceParts[0]
                            val sourcePort = sourceParts[1].toInt()
                            val destIp = destParts[0]
                            val destPort = destParts[1].toInt()

                            // Create new channel
                            val newChannel = SocketChannel.open()
                            protect(newChannel.socket())
                            newChannel.configureBlocking(false)

                            // Connect
                            val destAddress = InetSocketAddress(destIp, destPort)
                            newChannel.connect(destAddress)

                            // Register with selector
                            newChannel.register(selector, SelectionKey.OP_CONNECT, connectionKey)

                            // Update map
                            tcpConnections[connectionKey] = newChannel

                            Log.d(TAG, "Created new connection attempt for $connectionKey")
                        }
                    } catch (retryErr: Exception) {
                        Log.e(TAG, "Failed to retry connection: ${retryErr.message}")
                        tcpConnections.remove(connectionKey)
                        tcpConnectionStates.remove(connectionKey)
                    }
                } else {
                    // Give up after retries
                    key.cancel()
                    try { channel.close() } catch (_: Exception) { }
                    tcpConnections.remove(connectionKey)
                    tcpConnectionStates.remove(connectionKey)
                }
            }
        }
    }

    private fun handleReadable(key: SelectionKey, buffer: ByteBuffer, outStream: FileOutputStream) {
        val connectionKey = key.attachment() as String
        val parts = connectionKey.split("-")
        val sourceParts = parts[0].split(":")
        val destParts = parts[1].split(":")

        // Need special handling for IPv6 addresses which contain multiple colons
        val isIpv6 = sourceParts.size > 2 || destParts.size > 2

        // Extract source and destination differently for IPv4 and IPv6
        val sourceIp: String
        val destIp: String
        val sourcePort: Int
        val destPort: Int

        // Parse connection info
        if (isIpv6) {
            // For IPv6, the last part is the port
            sourcePort = sourceParts.last().toInt()
            destPort = destParts.last().toInt()

            // And the address is everything else
            sourceIp = sourceParts.dropLast(1).joinToString(":")
            destIp = destParts.dropLast(1).joinToString(":")
        } else {
            // Standard IPv4 handling
            sourceIp = sourceParts[0]
            sourcePort = sourceParts[1].toInt()
            destIp = destParts[0]
            destPort = destParts[1].toInt()
        }

        // Clear buffer for new data
        buffer.clear()

        try {
            if (key.channel() is SocketChannel) {
                // TCP channel
                val channel = key.channel() as SocketChannel
                val bytesRead = channel.read(buffer)

                // Reverse key for looking up connection state
                val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                val connectionState = tcpConnectionStates[reversedKey]

                if (bytesRead <= 0) {
                    // Connection closed or error
                    if (bytesRead < 0) {
                        if (DEBUG_CONNECTIONS) Log.d(TAG, "TCP connection closed: $connectionKey")

                        // Set connection state if exists
                        if (connectionState != null) {
                            connectionState.state = TcpState.CLOSE_WAIT
                        }

                        // For clean TCP termination, we should send a FIN packet here
                        if (connectionState != null) {
                            // Create a FIN packet
                            val finBuffer = ByteBuffer.allocate(0)  // No data
                            createAndSendTcpPacketWithFlags(
                                destIp, sourceIp, destPort, sourcePort,
                                finBuffer, 0, outStream, true
                            )

                            if (DEBUG_CONNECTIONS) Log.d(TAG, "Sent FIN packet for closed connection")
                            connectionState.state = TcpState.LAST_ACK
                        }

                        channel.close()
                        key.cancel()
                        tcpConnections.remove(connectionKey)
                        tcpConnectionStates.remove(reversedKey)
                    }
                    return
                }

                // Create or update connection state for this flow
                val state = connectionState ?: TcpConnectionState(reversedKey).apply {
                    tcpConnectionStates[reversedKey] = this
                    state = TcpState.ESTABLISHED
                }

                // Update remote sequence number
                state.remoteSeqNum += bytesRead

                if (DEBUG_FORWARDING) {
                    Log.d(TAG, "TCP received $bytesRead bytes from $destIp:$destPort")
                }

                // Prepare buffer for sending
                buffer.flip()

                // Create and send response packet based on IP version
                if (isIpv6) {
                    createAndSendTcpPacketIpv6(destIp, sourceIp, destPort, sourcePort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv6 TCP response delivered to app: $sourceIp:$sourcePort ($bytesRead bytes)")
                } else {
                    createAndSendTcpPacket(destIp, sourceIp, destPort, sourcePort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv4 TCP response delivered to app: $sourceIp:$sourcePort ($bytesRead bytes)")
                }
            } else if (key.channel() is DatagramChannel) {
                // UDP handling (remains largely unchanged)
                val channel = key.channel() as DatagramChannel
                val bytesRead = channel.read(buffer)

                if (bytesRead <= 0) return

                if (DEBUG_FORWARDING) {
                    Log.d(TAG, "UDP received $bytesRead bytes from $destIp:$destPort")
                }

                // Prepare buffer for sending
                buffer.flip()

                // Create and send response packet based on IP version
                if (isIpv6) {
                    createAndSendUdpPacketIpv6(destIp, sourceIp, destPort, sourcePort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv6 UDP response delivered to app: $sourceIp:$sourcePort ($bytesRead bytes)")
                } else {
                    createAndSendUdpPacket(destIp, sourceIp, destPort, sourcePort, buffer, bytesRead, outStream)
                    Log.d(TAG, "IPv4 UDP response delivered to app: $sourceIp:$sourcePort ($bytesRead bytes)")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling readable channel: ${e.message}", e)
            try {
                key.cancel()
                key.channel().close()

                if (key.channel() is SocketChannel) {
                    tcpConnections.remove(connectionKey)
                    val reversedKey = "$destIp:$destPort-$sourceIp:$sourcePort"
                    tcpConnectionStates.remove(reversedKey)
                } else if (key.channel() is DatagramChannel) {
                    udpConnections.remove(connectionKey)
                }
            } catch (closeErr: Exception) {
                Log.e(TAG, "Error cleaning up channel resources", closeErr)
            }
        }
    }

    // New helper method to handle TCP packets with specific flags
    private fun createAndSendTcpPacketWithFlags(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream,
        isFin: Boolean = false
    ) {
        val connectionKey = "$destIp:$destPort-$sourceIp:$sourcePort"  // Reversed for response
        try {
            // Get connection state
            val connectionState = tcpConnectionStates[connectionKey] ?: return

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

            // Sequence number
            tcpHeader.putInt(4, connectionState.localSeqNum.toInt())

            // ACK number
            tcpHeader.putInt(8, connectionState.remoteSeqNum.toInt())

            // Set flags based on parameters
            var flags = 0x10  // ACK is always set
            if (isFin) flags = flags or 0x01  // FIN flag

            // Data offset and flags
            tcpHeader.put(12, (5 shl 4).toByte())  // Header length 5 words (20 bytes)
            tcpHeader.put(13, flags.toByte())

            // Window size
            tcpHeader.putShort(14, connectionState.windowSize.toShort())

            // Checksum and urgent pointer
            tcpHeader.putShort(16, 0)  // Checksum (calculated later)
            tcpHeader.putShort(18, 0)  // Urgent pointer

            // Calculate checksums
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

            // Create combined data for TCP checksum
            val payloadData = ByteArray(payloadSize)
            if (payloadSize > 0) {
                payload.get(payloadData)
            }

            val tcpChecksumData = ByteArray(pseudoHeader.capacity() + tcpHeader.capacity() + payloadSize)
            System.arraycopy(pseudoHeader.array(), 0, tcpChecksumData, 0, pseudoHeader.capacity())
            System.arraycopy(tcpHeader.array(), 0, tcpChecksumData, pseudoHeader.capacity(), tcpHeader.capacity())
            if (payloadSize > 0) {
                System.arraycopy(payloadData, 0, tcpChecksumData, pseudoHeader.capacity() + tcpHeader.capacity(), payloadSize)
            }

            val tcpChecksum = calculateChecksumImproved(tcpChecksumData)
            tcpHeader.putShort(16, tcpChecksum)

            // Calculate IP checksum
            val ipChecksum = calculateChecksumImproved(ipHeader.array())
            ipHeader.putShort(10, ipChecksum)

            // Build and send the complete packet
            val packet = ByteBuffer.allocate(totalLength)
            ipHeader.position(0)
            tcpHeader.position(0)

            packet.put(ipHeader)
            packet.put(tcpHeader)
            if (payloadSize > 0) {
                packet.put(payloadData)
            }

            outStream.write(packet.array(), 0, totalLength)

            // If sending FIN, increment seq num by 1
            if (isFin) {
                connectionState.localSeqNum += 1
                Log.d(TAG, "TCP FIN sent: $sourceIp:$sourcePort -> $destIp:$destPort")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending TCP packet with flags: ${e.message}", e)
        }
    }

    private fun createAndSendTcpPacket(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteBuffer,
        payloadSize: Int,
        outStream: FileOutputStream
    ) {
        val connectionKey = "$destIp:$destPort-$sourceIp:$sourcePort"  // Reversed for response
        try {
            // Get or create connection state
            var connectionState = tcpConnectionStates[connectionKey]
            if (connectionState == null) {
                connectionState = TcpConnectionState(connectionKey)
                connectionState.state = TcpState.ESTABLISHED  // Assume established for responses
                tcpConnectionStates[connectionKey] = connectionState
            }

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

            // Sequence number
            tcpHeader.putInt(4, connectionState.localSeqNum.toInt())

            // ACK number - acknowledge all data received
            tcpHeader.putInt(8, connectionState.remoteSeqNum.toInt())

            // Data offset and flags - always ACK for responses
            tcpHeader.put(12, (5 shl 4).toByte())  // Header length 5 words (20 bytes)
            val flags = if (payloadSize > 0) 0x18.toByte() else 0x10.toByte() // PSH+ACK if data, otherwise just ACK
            tcpHeader.put(13, flags)

            // Window size
            tcpHeader.putShort(14, connectionState.windowSize.toShort())

            // Checksum and urgent pointer
            tcpHeader.putShort(16, 0)  // Checksum (calculated later)
            tcpHeader.putShort(18, 0)  // Urgent pointer

            // 3. Calculate checksums
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

            // Calculate TCP checksum - including both pseudo-header and payload
            val tcpChecksumData = ByteArray(pseudoHeader.capacity() + tcpHeader.capacity() + payloadData.size)
            System.arraycopy(pseudoHeader.array(), 0, tcpChecksumData, 0, pseudoHeader.capacity())
            System.arraycopy(tcpHeader.array(), 0, tcpChecksumData, pseudoHeader.capacity(), tcpHeader.capacity())
            System.arraycopy(payloadData, 0, tcpChecksumData, pseudoHeader.capacity() + tcpHeader.capacity(), payloadData.size)

            val tcpChecksum = calculateChecksumImproved(tcpChecksumData)
            tcpHeader.putShort(16, tcpChecksum)

            // Calculate IP checksum
            val ipChecksum = calculateChecksumImproved(ipHeader.array())
            ipHeader.putShort(10, ipChecksum)

            // 4. Build and send the complete packet
            val packet = ByteBuffer.allocate(totalLength)
            ipHeader.position(0)
            tcpHeader.position(0)

            packet.put(ipHeader)
            packet.put(tcpHeader)
            packet.put(payloadData)

            outStream.write(packet.array(), 0, totalLength)

            // Update sequence number for next packet
            connectionState.localSeqNum += payloadSize

            // Update ACK sent
            connectionState.lastAckSent = connectionState.remoteSeqNum

            if (DEBUG_FORWARDING) {
                Log.d(TAG, "TCP response sent: $sourceIp:$sourcePort -> $destIp:$destPort " +
                        "(SEQ=${connectionState.localSeqNum}, ACK=${connectionState.remoteSeqNum})")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating TCP packet: ${e.message}", e)
        }
    }

    // Improved checksum calculation
    private fun calculateChecksumImproved(data: ByteArray): Short {
        var sum = 0
        var length = data.size
        var i = 0

        // Handle complete 16-bit chunks
        while (length > 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
            length -= 2
        }

        // Handle any remaining byte
        if (length > 0) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        // Add carries
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        // Take one's complement
        return ((sum.inv()) and 0xFFFF).toShort()
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
        outStream: FileOutputStream
    ) {
        // For IPv6, constructing proper packets is complex and requires careful implementation
        // This is a simplified implementation
        try {
            val connectionKey = "$destIp:$destPort-$sourceIp:$sourcePort"  // Reversed for response

            // Get or create connection state
            var connectionState = tcpConnectionStates[connectionKey]
            if (connectionState == null) {
                connectionState = TcpConnectionState(connectionKey)
                tcpConnectionStates[connectionKey] = connectionState
            }

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

            // Sequence number
            tcpHeader.putInt(4, connectionState.localSeqNum.toInt())

            // ACK number
            tcpHeader.putInt(8, connectionState.remoteSeqNum.toInt())

            // Data offset and flags
            tcpHeader.put(12, (5 shl 4).toByte())  // 5 words (20 bytes), no reserved bits
            tcpHeader.put(13, 0x18.toByte())  // PSH + ACK flags

            // Window size
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

            // Update sequence number
            connectionState.localSeqNum += payloadSize

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
