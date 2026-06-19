package com.dpi.engine.service;

import com.dpi.engine.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DpiEngine {

    private static final Logger log = LoggerFactory.getLogger(DpiEngine.class);

    private final PacketParser          parser;
    private final FlowTable             flowTable;
    private final SimpMessagingTemplate ws;

    private final AtomicBoolean  processing     = new AtomicBoolean(false);
    private final AtomicInteger  packetCounter  = new AtomicInteger(0);
    private final AtomicLong     totalBytes     = new AtomicLong(0);
    private final AtomicInteger  tcpCount       = new AtomicInteger(0);
    private final AtomicInteger  udpCount       = new AtomicInteger(0);
    private final AtomicInteger  droppedCount   = new AtomicInteger(0);
    private final AtomicInteger  forwardedCount = new AtomicInteger(0);

    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    @Autowired
    public DpiEngine(PacketParser parser, FlowTable flowTable, SimpMessagingTemplate ws) {
        this.parser    = parser;
        this.flowTable = flowTable;
        this.ws        = ws;
    }

    public boolean isProcessing()     { return processing.get(); }
    public int  getTotalPackets()     { return packetCounter.get(); }
    public long getTotalBytes()       { return totalBytes.get(); }
    public int  getDroppedPackets()   { return droppedCount.get(); }
    public int  getForwardedPackets() { return forwardedCount.get(); }

    public void reset() {
        flowTable.clear();
        packetCounter.set(0);
        totalBytes.set(0);
        tcpCount.set(0);
        udpCount.set(0);
        droppedCount.set(0);
        forwardedCount.set(0);
    }

    @Async
    public void processPcapAsync(InputStream pcapStream, String filename) {
        if (!processing.compareAndSet(false, true)) {
            log.warn("Already processing a file.");
            return;
        }
        reset();

        long startMs = System.currentTimeMillis();
        PcapReader reader = new PcapReader();

        try {
            int linkType = reader.open(pcapStream);
            log.info("Processing PCAP '{}' — link type={}", filename, linkType);

            ws.convertAndSend("/topic/status",
                Map.of("status", "started", "file", filename));

            PcapReader.RawPacket raw;
            while ((raw = reader.readNext()) != null) {
                int pktNum = packetCounter.incrementAndGet();
                totalBytes.addAndGet(raw.inclLen());

                PacketResult result = processPacket(pktNum, raw);

                if (pktNum <= 5000 || pktNum % 50 == 0) {
                    ws.convertAndSend("/topic/packets", result);
                }
                if (pktNum % 200 == 0) Thread.sleep(5);
            }

            DpiReport report = buildReport(filename, System.currentTimeMillis() - startMs);
            ws.convertAndSend("/topic/report", report);
            ws.convertAndSend("/topic/status",
                Map.of("status", "complete", "totalPackets", packetCounter.get()));

            log.info("Done — {} packets in {}ms",
                packetCounter.get(), System.currentTimeMillis() - startMs);

        } catch (Exception e) {
            log.error("Error processing PCAP", e);
            ws.convertAndSend("/topic/status",
                Map.of("status", "error", "message", e.getMessage()));
        } finally {
            reader.close();
            processing.set(false);
        }
    }

    private PacketResult processPacket(int pktNum, PcapReader.RawPacket raw) {
        String ts = formatTimestamp(raw.tsSec(), raw.tsUsec());
        PacketParser.ParsedPacket parsed = parser.parse(raw.data());

        if (!parsed.valid) {
            forwardedCount.incrementAndGet();
            return unknownResult(pktNum, raw.inclLen(), ts);
        }

        if (parsed.isTcp) tcpCount.incrementAndGet();
        if (parsed.isUdp) udpCount.incrementAndGet();

        FiveTuple tuple = parsed.tuple;
        Flow flow = flowTable.getOrCreate(tuple);
        flow.addPacket(raw.inclLen());

        // TLS SNI extraction
        if (parsed.isTcp && tuple.getDstPort() == 443 && flow.getSni().isBlank()) {
            String sni = TlsSniExtractor.extract(parsed.tcpUdpPayload);
            if (!sni.isBlank()) {
                flow.setSni(sni);
                flow.setAppType(AppType.fromSni(sni));
            }
        }

        // HTTP Host header
        if (parsed.isTcp && tuple.getDstPort() == 80 && flow.getAppType() == AppType.UNKNOWN) {
            String host = extractHttpHost(parsed.tcpUdpPayload);
            if (!host.isBlank()) {
                flow.setSni(host);
                flow.setAppType(AppType.fromSni(host));
            } else {
                flow.setAppType(AppType.HTTP);
            }
        }

        // DNS
        if (tuple.getDstPort() == 53 && flow.getAppType() == AppType.UNKNOWN)
            flow.setAppType(AppType.DNS);

        // NTP
        if (tuple.getDstPort() == 123 && flow.getAppType() == AppType.UNKNOWN)
            flow.setAppType(AppType.NTP);

        // Fallback by port
        if (flow.getAppType() == AppType.UNKNOWN)
            flow.setAppType(AppType.fromPort(tuple.getDstPort(), tuple.getProtocol()));

        // Blocking
        boolean blocked = flowTable.isAppBlocked(flow.getAppType());
        flow.setBlocked(blocked);
        if (blocked) droppedCount.incrementAndGet();
        else         forwardedCount.incrementAndGet();

        return new PacketResult(pktNum, tuple, raw.inclLen(),
            flow.getAppType(), flow.getSni(), blocked, ts);
    }

    public DpiReport buildReport(String filename, long durationMs) {
        DpiReport report = new DpiReport();
        report.setFilename(filename);
        report.setTotalPackets(packetCounter.get());
        report.setTotalBytes(totalBytes.get());
        report.setTcpPackets(tcpCount.get());
        report.setUdpPackets(udpCount.get());
        report.setForwardedPackets(forwardedCount.get());
        report.setDroppedPackets(droppedCount.get());
        report.setTotalFlows(flowTable.size());
        report.setProcessingTimeMs(durationMs);

        Map<String, Integer> breakdown = new LinkedHashMap<>();
        Map<String, String>  colors    = new LinkedHashMap<>();

        for (Map.Entry<AppType, Long> e : flowTable.packetsByApp().entrySet()) {
            breakdown.put(e.getKey().getDisplayName(), e.getValue().intValue());
            colors.put(e.getKey().getDisplayName(), e.getKey().getColor());
        }
        report.setAppBreakdown(breakdown);
        report.setAppColors(colors);
        report.setHttpsFlows((int) flowTable.allFlows().stream()
            .filter(f -> f.getAppType() == AppType.HTTPS || !f.getSni().isBlank())
            .count());

        List<DpiReport.SniEntry> snis = new ArrayList<>();
        flowTable.uniqueSnis().forEach((sni, app) -> {
            int pkts = flowTable.allFlows().stream()
                .filter(f -> f.getSni().equals(sni))
                .mapToInt(Flow::getPacketCount).sum();
            snis.add(new DpiReport.SniEntry(sni, app.getDisplayName(), app.getColor(), pkts));
        });
        snis.sort(Comparator.comparingInt(DpiReport.SniEntry::packets).reversed());
        report.setDetectedSnis(snis.subList(0, Math.min(snis.size(), 50)));

        report.setBlockedFlows(
            flowTable.allFlows().stream()
                .filter(Flow::isBlocked)
                .map(f -> f.getTuple() + " [" + f.getAppType().getDisplayName() + "]")
                .limit(100)
                .toList()
        );
        return report;
    }

    private PacketResult unknownResult(int num, int len, String ts) {
        return new PacketResult(num, new FiveTuple(0,0,0,0,0),
            len, AppType.UNKNOWN, "", false, ts);
    }

    private String formatTimestamp(long sec, long usec) {
        LocalDateTime ldt = LocalDateTime.ofEpochSecond(sec, (int)(usec * 1000), ZoneOffset.UTC);
        return ldt.format(TS_FMT);
    }

    private String extractHttpHost(byte[] payload) {
        if (payload == null || payload.length < 10) return "";
        String text = new String(payload, 0, Math.min(payload.length, 1024));
        int idx = text.toLowerCase().indexOf("host:");
        if (idx < 0) return "";
        int start = idx + 5;
        int end = text.indexOf('\n', start);
        if (end < 0) end = text.length();
        return text.substring(start, end).strip().replaceAll(":.*", "");
    }
}
