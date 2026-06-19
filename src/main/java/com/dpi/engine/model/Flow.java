package com.dpi.engine.model;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a stateful network flow (connection).
 * One Flow per unique FiveTuple.
 */
public class Flow {

    private final FiveTuple tuple;
    private volatile AppType appType = AppType.UNKNOWN;
    private volatile String  sni     = "";
    private volatile boolean blocked = false;

    private final AtomicInteger packetCount = new AtomicInteger(0);
    private final AtomicLong    byteCount   = new AtomicLong(0);

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple getTuple()      { return tuple; }
    public AppType   getAppType()    { return appType; }
    public String    getSni()        { return sni; }
    public boolean   isBlocked()     { return blocked; }
    public int       getPacketCount(){ return packetCount.get(); }
    public long      getByteCount()  { return byteCount.get(); }

    public void setAppType(AppType t) { this.appType = t; }
    public void setSni(String s)      { this.sni = s; }
    public void setBlocked(boolean b) { this.blocked = b; }

    public void addPacket(int bytes) {
        packetCount.incrementAndGet();
        byteCount.addAndGet(bytes);
    }

    @Override
    public String toString() {
        return tuple + " app=" + appType.getDisplayName() +
               " sni=" + sni + " pkts=" + packetCount +
               (blocked ? " [BLOCKED]" : "");
    }
}
