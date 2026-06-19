package com.dpi.engine.model;

import java.util.Objects;

/**
 * Uniquely identifies a network flow (connection).
 * Same five-tuple = same flow.
 */
public class FiveTuple {
    private final long srcIp;
    private final long dstIp;
    private final int  srcPort;
    private final int  dstPort;
    private final int  protocol;  // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    public long getSrcIp()    { return srcIp; }
    public long getDstIp()    { return dstIp; }
    public int  getSrcPort()  { return srcPort; }
    public int  getDstPort()  { return dstPort; }
    public int  getProtocol() { return protocol; }

    public String getSrcIpStr() { return ipLongToString(srcIp); }
    public String getDstIpStr() { return ipLongToString(dstIp); }
    public String getProtocolStr() {
        return switch (protocol) { case 6 -> "TCP"; case 17 -> "UDP"; default -> "OTHER"; };
    }

    public static String ipLongToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8)  & 0xFF) + "." +
               (ip         & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return getSrcIpStr() + ":" + srcPort + " → " + getDstIpStr() + ":" + dstPort +
               " [" + getProtocolStr() + "]";
    }
}
