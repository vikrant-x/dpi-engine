package com.dpi.engine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * DPI Engine - Deep Packet Inspection System
 * Java Edition (Spring Boot 3.2 / Java 17)
 *
 * Inspects PCAP captures, classifies application traffic,
 * extracts TLS SNI, and enforces blocking rules.
 */
@SpringBootApplication
@EnableAsync
public class DpiEngineApplication {
    public static void main(String[] args) {
        SpringApplication.run(DpiEngineApplication.class, args);
        System.out.println("""
            ╔══════════════════════════════════════════════════╗
            ║        DPI ENGINE v2.0  —  Java Edition          ║
            ║        Deep Packet Inspection System             ║
            ╠══════════════════════════════════════════════════╣
            ║  Server running at: http://localhost:8080        ║
            ╚══════════════════════════════════════════════════╝
            """);
    }
}
