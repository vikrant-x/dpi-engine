package com.dpi.engine.service;

import org.springframework.stereotype.Component;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads Wireshark/tcpdump PCAP files.
 *
 * PCAP Format:
 *   Global Header (24 bytes) — magic, version, snaplen, link type
 *   Repeated:
 *     Packet Header (16 bytes) — ts_sec, ts_usec, incl_len, orig_len
 *     Packet Data   (incl_len bytes)
 */
@Component
public class PcapReader {

    public static final int PCAP_MAGIC_LE = 0xa1b2c3d4; // little-endian
    public static final int PCAP_MAGIC_BE = 0xd4c3b2a1; // big-endian (swapped)

    /** Simple container for one raw packet */
    public record RawPacket(
        long   tsSec,
        long   tsUsec,
        int    inclLen,
        int    origLen,
        byte[] data
    ) {}

    private DataInputStream dis;
    private boolean         swapped;   // true if big-endian file
    private boolean         opened;

    /** Open a PCAP InputStream, validate header. Returns link type (1=Ethernet). */
    public int open(InputStream in) throws IOException {
        dis = new DataInputStream(new BufferedInputStream(in));

        // Read magic to determine byte order
        int magic = readInt32LE(dis);
        if (magic == PCAP_MAGIC_LE) {
            swapped = false;
        } else if (magic == PCAP_MAGIC_BE) {
            swapped = true;
        } else {
            throw new IOException("Not a valid PCAP file (magic=" + Integer.toHexString(magic) + ")");
        }

        // Skip version_major(2), version_minor(2), thiszone(4), sigfigs(4), snaplen(4)
        readUint16(); readUint16();
        readUint32(); readUint32(); readUint32();

        // Network/link type
        int linkType = (int) readUint32();
        opened = true;
        return linkType;
    }

    /** Read the next packet. Returns null when file is exhausted. */
    public RawPacket readNext() throws IOException {
        if (!opened) throw new IllegalStateException("Call open() first");
        try {
            long tsSec   = readUint32();
            long tsUsec  = readUint32();
            int  inclLen = (int) readUint32();
            int  origLen = (int) readUint32();

            if (inclLen < 0 || inclLen > 65535) return null; // sanity

            byte[] data = new byte[inclLen];
            dis.readFully(data);

            return new RawPacket(tsSec, tsUsec, inclLen, origLen, data);
        } catch (EOFException e) {
            return null; // normal end of file
        }
    }

    public void close() {
        if (dis != null) {
            try { dis.close(); } catch (IOException ignored) {}
        }
        opened = false;
    }

    /* ── Internal byte-order helpers ── */

    private int readInt32LE(DataInputStream s) throws IOException {
        byte[] b = new byte[4];
        s.readFully(b);
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    private long readUint32() throws IOException {
        byte[] b = new byte[4];
        dis.readFully(b);
        if (!swapped) {
            // little-endian
            return ((b[0] & 0xFFL)) | ((b[1] & 0xFFL) << 8) |
                   ((b[2] & 0xFFL) << 16) | ((b[3] & 0xFFL) << 24);
        } else {
            // big-endian
            return ((b[3] & 0xFFL)) | ((b[2] & 0xFFL) << 8) |
                   ((b[1] & 0xFFL) << 16) | ((b[0] & 0xFFL) << 24);
        }
    }

    private int readUint16() throws IOException {
        byte[] b = new byte[2];
        dis.readFully(b);
        if (!swapped) {
            return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8);
        } else {
            return (b[1] & 0xFF) | ((b[0] & 0xFF) << 8);
        }
    }

    /** Read a big-endian uint16 from byte array */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read a big-endian uint32 from byte array */
    public static long readUint32BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFFL) << 24) |
               ((data[offset + 1] & 0xFFL) << 16) |
               ((data[offset + 2] & 0xFFL) << 8)  |
               (data[offset + 3]  & 0xFFL);
    }
}
