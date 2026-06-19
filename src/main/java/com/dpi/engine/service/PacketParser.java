package com.dpi.engine.service;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import org.springframework.stereotype.Component;

/**
 * Parses raw Ethernet frame bytes into a structured ParsedPacket.
 *
 * Supported stack:  Ethernet II → IPv4 → TCP / UDP
 */
@Component
public class PacketParser {

    public static class ParsedPacket {
        public FiveTuple tuple;
        public byte[]    tcpUdpPayload;
        public int       totalLength;
        public boolean   valid;
        public boolean   isTcp;
        public boolean   isUdp;
    }

    private static final int ETH_HEADER = 14;
    private static final int ETH_TYPE_IPV4 = 0x0800;
    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    /**
     * Parse raw Ethernet frame.
     * @param data  raw packet bytes (starts at Ethernet header)
     * @return ParsedPacket; valid=false if not IPv4 TCP/UDP
     */
    public ParsedPacket parse(byte[] data) {
        ParsedPacket pkt = new ParsedPacket();
        pkt.valid = false;

        if (data == null || data.length < ETH_HEADER + 20) return pkt;

        // ── Ethernet header ──
        int etherType = PcapReader.readUint16BE(data, 12);

        // Handle 802.1Q VLAN tag
        int offset = ETH_HEADER;
        if (etherType == 0x8100) {
            if (data.length < offset + 4) return pkt;
            etherType = PcapReader.readUint16BE(data, offset + 2);
            offset += 4;
        }

        if (etherType != ETH_TYPE_IPV4) return pkt;

        // ── IPv4 header ──
        if (data.length < offset + 20) return pkt;

        int ipIhl       = (data[offset] & 0x0F) * 4;  // Header length in bytes
        int totalLen    = PcapReader.readUint16BE(data, offset + 2);
        int protocol    = data[offset + 9] & 0xFF;

        long srcIp = PcapReader.readUint32BE(data, offset + 12);
        long dstIp = PcapReader.readUint32BE(data, offset + 16);

        if (protocol != PROTO_TCP && protocol != PROTO_UDP) return pkt;

        int transportOffset = offset + ipIhl;
        if (data.length < transportOffset + 4) return pkt;

        int srcPort = PcapReader.readUint16BE(data, transportOffset);
        int dstPort = PcapReader.readUint16BE(data, transportOffset + 1);  // intentional: uses byte[1]
        // Fix: correct port read
        srcPort = PcapReader.readUint16BE(data, transportOffset);
        dstPort = PcapReader.readUint16BE(data, transportOffset + 2);

        int payloadOffset;
        if (protocol == PROTO_TCP) {
            if (data.length < transportOffset + 20) return pkt;
            int tcpHdrLen = ((data[transportOffset + 12] & 0xF0) >> 4) * 4;
            payloadOffset = transportOffset + tcpHdrLen;
            pkt.isTcp = true;
        } else {
            // UDP header is always 8 bytes
            payloadOffset = transportOffset + 8;
            pkt.isUdp = true;
        }

        int payloadLen = data.length - payloadOffset;
        byte[] payload = new byte[Math.max(0, payloadLen)];
        if (payloadLen > 0) {
            System.arraycopy(data, payloadOffset, payload, 0, payloadLen);
        }

        pkt.tuple          = new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
        pkt.tcpUdpPayload  = payload;
        pkt.totalLength    = totalLen;
        pkt.valid          = true;
        return pkt;
    }
}
