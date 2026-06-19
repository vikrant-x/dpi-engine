package com.dpi.engine.controller;

import com.dpi.engine.model.DpiReport;
import com.dpi.engine.service.DpiEngine;
import com.dpi.engine.service.FlowTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * HTTP controller — serves pages and REST endpoints.
 *
 * GET  /            → dashboard (index.html)
 * POST /api/analyze → upload & process PCAP
 * GET  /api/status  → current processing status
 * POST /api/block   → add blocked app
 * DELETE /api/block → remove blocked app
 * GET  /api/flows   → all flows JSON
 * GET  /api/report  → last report JSON
 */
@Controller
public class DpiController {

    private static final Logger log = LoggerFactory.getLogger(DpiController.class);

    private final DpiEngine  engine;
    private final FlowTable  flowTable;

    // Hold last report in memory
    private volatile DpiReport lastReport;

    @Autowired
    public DpiController(DpiEngine engine, FlowTable flowTable) {
        this.engine    = engine;
        this.flowTable = flowTable;
    }

    /* ── Page routes ── */

    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("processing", engine.isProcessing());
        model.addAttribute("blockedApps", flowTable.getBlockedApps());
        if (lastReport != null) model.addAttribute("report", lastReport);
        return "index";
    }

    /* ── REST: Upload & analyze PCAP ── */

    @PostMapping("/api/analyze")
    @ResponseBody
    public ResponseEntity<?> analyzePcap(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No file uploaded"));
        }
        if (engine.isProcessing()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Already processing a file. Please wait."));
        }

        String name = file.getOriginalFilename();
        log.info("Received PCAP upload: {} ({} bytes)", name, file.getSize());

        try {
            engine.processPcapAsync(file.getInputStream(), name);
            return ResponseEntity.ok(Map.of(
                "message", "Processing started",
                "file", name,
                "size", file.getSize()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(Map.of("error", e.getMessage()));
        }
    }

    /* ── REST: Status ── */

    @GetMapping("/api/status")
    @ResponseBody
    public Map<String, Object> status() {
        return Map.of(
            "processing",   engine.isProcessing(),
            "totalPackets", engine.getTotalPackets(),
            "totalBytes",   engine.getTotalBytes(),
            "dropped",      engine.getDroppedPackets(),
            "forwarded",    engine.getForwardedPackets(),
            "flows",        flowTable.size()
        );
    }

    /* ── REST: Blocking rules ── */

    @PostMapping("/api/block")
    @ResponseBody
    public ResponseEntity<?> blockApp(@RequestBody Map<String, String> body) {
        String app = body.getOrDefault("app", "").trim();
        if (app.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "App name required"));
        flowTable.blockApp(app);
        log.info("Blocked: {}", app);
        return ResponseEntity.ok(Map.of("blocked", app, "allBlocked", flowTable.getBlockedApps()));
    }

    @DeleteMapping("/api/block")
    @ResponseBody
    public ResponseEntity<?> unblockApp(@RequestBody Map<String, String> body) {
        String app = body.getOrDefault("app", "").trim();
        flowTable.unblockApp(app);
        return ResponseEntity.ok(Map.of("unblocked", app, "allBlocked", flowTable.getBlockedApps()));
    }

    @GetMapping("/api/block")
    @ResponseBody
    public Set<String> getBlockedApps() {
        return flowTable.getBlockedApps();
    }

    /* ── REST: Report ── */

    @GetMapping("/api/report")
    @ResponseBody
    public ResponseEntity<?> getReport() {
        if (lastReport == null)
            return ResponseEntity.ok(Map.of("message", "No report yet. Upload a PCAP file."));
        return ResponseEntity.ok(lastReport);
    }

    @PostMapping("/api/report")  // internal: called by engine after processing
    @ResponseBody
    public void saveReport(@RequestBody DpiReport report) {
        this.lastReport = report;
    }

    /* ── REST: Flows ── */

    @GetMapping("/api/flows")
    @ResponseBody
    public List<Map<String, Object>> flows() {
        return flowTable.allFlows().stream().limit(500).map(f -> Map.<String, Object>of(
            "src",      f.getTuple().getSrcIpStr() + ":" + f.getTuple().getSrcPort(),
            "dst",      f.getTuple().getDstIpStr() + ":" + f.getTuple().getDstPort(),
            "proto",    f.getTuple().getProtocolStr(),
            "app",      f.getAppType().getDisplayName(),
            "color",    f.getAppType().getColor(),
            "sni",      f.getSni(),
            "packets",  f.getPacketCount(),
            "bytes",    f.getByteCount(),
            "blocked",  f.isBlocked()
        )).toList();
    }
}
