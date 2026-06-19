package com.dpi.engine.service;

/**
 * Extracts the SNI (Server Name Indication) from a TLS ClientHello message.
 *
 * TLS Record Layout:
 *   [0]    Content Type      (0x16 = Handshake)
 *   [1-2]  TLS Version       (0x0301..0x0303)
 *   [3-4]  Record Length
 *   [5]    Handshake Type    (0x01 = ClientHello)
 *   [6-8]  Handshake Length
 *   [9-10] Client Version
 *   [11-42] Random (32 bytes)
 *   [43]   Session ID Length
 *   ...    Cipher Suites, Compression, Extensions
 *   Extension 0x0000 = SNI
 */
public class TlsSniExtractor {

    private static final byte TLS_CONTENT_HANDSHAKE = 0x16;
    private static final byte TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int  EXT_SNI = 0x0000;
    private static final int  SNI_TYPE_HOST = 0x00;

    /** Returns SNI hostname or empty string if not found / not a ClientHello */
    public static String extract(byte[] tcpPayload) {
        if (tcpPayload == null || tcpPayload.length < 43) return "";

        // TLS Record header
        if ((tcpPayload[0] & 0xFF) != (TLS_CONTENT_HANDSHAKE & 0xFF)) return "";

        int tlsVersion = PcapReader.readUint16BE(tcpPayload, 1);
        if (tlsVersion < 0x0301 || tlsVersion > 0x0304) return ""; // TLS 1.0–1.3

        // Handshake header
        if ((tcpPayload[5] & 0xFF) != (TLS_HANDSHAKE_CLIENT_HELLO & 0xFF)) return "";

        int pos = 9; // Skip: record hdr(5) + hs type(1) + hs len(3) = 9 → client version
        pos += 2;    // Client Version
        pos += 32;   // Random

        if (pos >= tcpPayload.length) return "";

        // Session ID
        int sessionIdLen = tcpPayload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        if (pos + 2 > tcpPayload.length) return "";

        // Cipher Suites
        int cipherLen = PcapReader.readUint16BE(tcpPayload, pos);
        pos += 2 + cipherLen;

        if (pos + 1 > tcpPayload.length) return "";

        // Compression Methods
        int compLen = tcpPayload[pos] & 0xFF;
        pos += 1 + compLen;

        if (pos + 2 > tcpPayload.length) return ""; // no extensions

        // Extensions total length
        int extTotal = PcapReader.readUint16BE(tcpPayload, pos);
        pos += 2;
        int extEnd = pos + extTotal;

        // Walk extensions
        while (pos + 4 <= extEnd && pos + 4 <= tcpPayload.length) {
            int extType = PcapReader.readUint16BE(tcpPayload, pos);
            int extLen  = PcapReader.readUint16BE(tcpPayload, pos + 2);
            pos += 4;

            if (extType == EXT_SNI) {
                // SNI list length
                if (pos + 2 > tcpPayload.length) return "";
                int sniListLen = PcapReader.readUint16BE(tcpPayload, pos);
                pos += 2;

                // SNI type
                if (pos + 3 > tcpPayload.length) return "";
                int sniType    = tcpPayload[pos] & 0xFF;
                int sniNameLen = PcapReader.readUint16BE(tcpPayload, pos + 1);
                pos += 3;

                if (sniType == SNI_TYPE_HOST && pos + sniNameLen <= tcpPayload.length) {
                    return new String(tcpPayload, pos, sniNameLen);
                }
                return "";
            }
            pos += extLen;
        }
        return "";
    }
}
