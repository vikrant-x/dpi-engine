package com.dpi.engine.model;

import java.util.*;

/**
 * Summary report produced after processing a PCAP file.
 */
public class DpiReport {
    private int    totalPackets;
    private long   totalBytes;
    private int    tcpPackets;
    private int    udpPackets;
    private int    forwardedPackets;
    private int    droppedPackets;
    private int    totalFlows;
    private int    httpsFlows;
    private long   processingTimeMs;
    private String filename;

    // AppType → packet count
    private Map<String, Integer> appBreakdown = new LinkedHashMap<>();
    // AppType → color
    private Map<String, String>  appColors    = new LinkedHashMap<>();
    // Detected SNIs
    private List<SniEntry>       detectedSnis = new ArrayList<>();
    // Blocked flows
    private List<String>         blockedFlows = new ArrayList<>();

    public record SniEntry(String sni, String appType, String color, int packets) {}

    /* ── getters & setters ── */
    public int    getTotalPackets()      { return totalPackets; }
    public long   getTotalBytes()        { return totalBytes; }
    public int    getTcpPackets()        { return tcpPackets; }
    public int    getUdpPackets()        { return udpPackets; }
    public int    getForwardedPackets()  { return forwardedPackets; }
    public int    getDroppedPackets()    { return droppedPackets; }
    public int    getTotalFlows()        { return totalFlows; }
    public int    getHttpsFlows()        { return httpsFlows; }
    public long   getProcessingTimeMs()  { return processingTimeMs; }
    public String getFilename()          { return filename; }
    public Map<String,Integer> getAppBreakdown() { return appBreakdown; }
    public Map<String,String>  getAppColors()    { return appColors; }
    public List<SniEntry>      getDetectedSnis() { return detectedSnis; }
    public List<String>        getBlockedFlows() { return blockedFlows; }

    public void setTotalPackets(int v)     { this.totalPackets = v; }
    public void setTotalBytes(long v)      { this.totalBytes = v; }
    public void setTcpPackets(int v)       { this.tcpPackets = v; }
    public void setUdpPackets(int v)       { this.udpPackets = v; }
    public void setForwardedPackets(int v) { this.forwardedPackets = v; }
    public void setDroppedPackets(int v)   { this.droppedPackets = v; }
    public void setTotalFlows(int v)       { this.totalFlows = v; }
    public void setHttpsFlows(int v)       { this.httpsFlows = v; }
    public void setProcessingTimeMs(long v){ this.processingTimeMs = v; }
    public void setFilename(String v)      { this.filename = v; }
    public void setAppBreakdown(Map<String,Integer> v) { this.appBreakdown = v; }
    public void setAppColors(Map<String,String> v)     { this.appColors = v; }
    public void setDetectedSnis(List<SniEntry> v)      { this.detectedSnis = v; }
    public void setBlockedFlows(List<String> v)        { this.blockedFlows = v; }

    public double getDropRate() {
        if (totalPackets == 0) return 0.0;
        return (droppedPackets * 100.0) / totalPackets;
    }
    public double getForwardRate() {
        if (totalPackets == 0) return 0.0;
        return (forwardedPackets * 100.0) / totalPackets;
    }
    public String getTotalBytesFormatted() {
        if (totalBytes < 1024)       return totalBytes + " B";
        if (totalBytes < 1024*1024)  return String.format("%.1f KB", totalBytes/1024.0);
        return String.format("%.2f MB", totalBytes/(1024.0*1024));
    }
}
