# 🔬 DPI Engine — Deep Packet Inspection System
## Java Edition (Spring Boot 3.2 · Java 17)

> Real-time packet inspection, TLS SNI extraction, app classification,
> traffic blocking — all in a professional white-UI web dashboard.

---

## 🚀 How to Run

### Prerequisites
| Tool | Version |
|------|---------|
| Java JDK | 17 or higher |
| Maven | 3.8+ (or use `./mvnw` wrapper) |

### Step 1 — Check Java version
```bash
java -version
# Should show: openjdk 17... or higher
```

### Step 2 — Build the project
```bash
cd dpi-engine
mvn clean package -DskipTests
```

### Step 3 — Run
```bash
mvn spring-boot:run
```
**OR** run the built JAR directly:
```bash
java -jar target/dpi-engine-2.0.0.jar
```

### Step 4 — Open browser
```
http://localhost:8080
```

---

## 📦 How to Use

1. **Upload a PCAP file** — drag & drop or click "Choose File"
   - Works with `.pcap`, `.pcapng`, `.cap` files
   - Captured with Wireshark, tcpdump, tshark etc.

2. **Watch the live feed** — packets stream in real-time via WebSocket

3. **View charts** — app distribution (pie), timeline, protocol breakdown

4. **See SNI hostnames** — TLS ClientHello extraction shows which sites are visited

5. **Block apps** — click YouTube/Netflix/etc. chips to block that traffic

---

## 📁 Project Structure

```
dpi-engine/
├── pom.xml
└── src/main/
    ├── java/com/dpi/engine/
    │   ├── DpiEngineApplication.java      ← Main class
    │   ├── model/
    │   │   ├── AppType.java               ← App classification enum
    │   │   ├── FiveTuple.java             ← Flow key (src/dst IP+port+proto)
    │   │   ├── Flow.java                  ← Flow state tracker
    │   │   ├── PacketResult.java          ← Live feed DTO
    │   │   └── DpiReport.java             ← Final analysis report
    │   ├── service/
    │   │   ├── PcapReader.java            ← Binary PCAP parser
    │   │   ├── PacketParser.java          ← Ethernet/IP/TCP/UDP parser
    │   │   ├── TlsSniExtractor.java       ← TLS ClientHello SNI extractor
    │   │   ├── FlowTable.java             ← Concurrent flow tracking
    │   │   └── DpiEngine.java             ← Core inspection pipeline
    │   ├── controller/
    │   │   └── DpiController.java         ← REST + MVC endpoints
    │   └── config/
    │       └── WebSocketConfig.java       ← STOMP/WebSocket config
    └── resources/
        ├── application.properties
        └── templates/
            └── index.html                 ← Full UI (single page)
```

---

## 🌐 API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Dashboard UI |
| POST | `/api/analyze` | Upload & analyze PCAP |
| GET | `/api/status` | Current processing stats |
| GET | `/api/flows` | All tracked flows (JSON) |
| GET | `/api/report` | Last analysis report (JSON) |
| POST | `/api/block` | Block an app `{"app":"YouTube"}` |
| DELETE | `/api/block` | Unblock an app |

### WebSocket Topics
| Topic | Data |
|-------|------|
| `/topic/packets` | Live PacketResult stream |
| `/topic/report` | Final DpiReport on completion |
| `/topic/status` | Processing status updates |

---

## 🧪 Get Test PCAP Files

Free public PCAP samples:
- https://wiki.wireshark.org/SampleCaptures
- https://www.netresec.com/?page=PCAP4SICS
- Run Wireshark and capture your own!

---

## 🔧 Configuration (`application.properties`)

```properties
server.port=8080                          # Change port if needed
spring.servlet.multipart.max-file-size=500MB   # Max PCAP size
```

---

## 📊 Features

- ✅ Binary PCAP parsing (no external libraries needed)
- ✅ Ethernet II / IPv4 / TCP / UDP layer parsing
- ✅ TLS ClientHello SNI extraction (identifies HTTPS sites)
- ✅ HTTP Host header extraction
- ✅ 22 app types: YouTube, Netflix, WhatsApp, Telegram, etc.
- ✅ Real-time WebSocket live feed
- ✅ Interactive charts (Chart.js)
- ✅ Traffic blocking rules
- ✅ Concurrent flow tracking
- ✅ Professional white UI (Inter font, smooth animations)
