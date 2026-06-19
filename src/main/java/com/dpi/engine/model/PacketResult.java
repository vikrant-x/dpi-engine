package com.dpi.engine.model;

/**
 * DTO representing a single processed packet — sent to the UI live feed.
 */
public class PacketResult {
    private int    number;
    private String srcIp;
    private String dstIp;
    private int    srcPort;
    private int    dstPort;
    private String protocol;
    private int    length;
    private String appType;
    private String appColor;
    private String sni;
    private boolean blocked;
    private String  timestamp;

    public PacketResult() {}

    public PacketResult(int number, FiveTuple tuple, int length,
                        AppType app, String sni, boolean blocked, String ts) {
        this.number   = number;
        this.srcIp    = tuple.getSrcIpStr();
        this.dstIp    = tuple.getDstIpStr();
        this.srcPort  = tuple.getSrcPort();
        this.dstPort  = tuple.getDstPort();
        this.protocol = tuple.getProtocolStr();
        this.length   = length;
        this.appType  = app.getDisplayName();
        this.appColor = app.getColor();
        this.sni      = sni;
        this.blocked  = blocked;
        this.timestamp = ts;
    }

    public int     getNumber()   { return number; }
    public String  getSrcIp()    { return srcIp; }
    public String  getDstIp()    { return dstIp; }
    public int     getSrcPort()  { return srcPort; }
    public int     getDstPort()  { return dstPort; }
    public String  getProtocol() { return protocol; }
    public int     getLength()   { return length; }
    public String  getAppType()  { return appType; }
    public String  getAppColor() { return appColor; }
    public String  getSni()      { return sni; }
    public boolean isBlocked()   { return blocked; }
    public String  getTimestamp(){ return timestamp; }

    public void setNumber(int n)       { this.number = n; }
    public void setSrcIp(String s)     { this.srcIp = s; }
    public void setDstIp(String s)     { this.dstIp = s; }
    public void setSrcPort(int p)      { this.srcPort = p; }
    public void setDstPort(int p)      { this.dstPort = p; }
    public void setProtocol(String p)  { this.protocol = p; }
    public void setLength(int l)       { this.length = l; }
    public void setAppType(String a)   { this.appType = a; }
    public void setAppColor(String c)  { this.appColor = c; }
    public void setSni(String s)       { this.sni = s; }
    public void setBlocked(boolean b)  { this.blocked = b; }
    public void setTimestamp(String t) { this.timestamp = t; }
}
