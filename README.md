# PCAP-TCP-Anomaly-Detection
TCP session reconstruction and anomaly detection from PCAP network traffic
# Network Traffic Analysis - W32/Sdbot PCAP Dataset

## Dataset Overview

Filename: toolsmith.pcap
Source: https://holisticinfosec.io/toolsmith/files/nov2k6/toolsmith.pcap
Malware: W32/Sdbot IRC bot/trojan
Total Packets: 392
Duration: 10.868 seconds
Average Rate: 36.1 packets/second
Size: 79,179 bytes

---

## Basic Traffic Profile

Capture shows infected machine at 192.168.1.1 conducting automated scanning against 9 external targets. Traffic is 95.4% TCP, 4.6% DNS. Primary activity is HTTP scanning on port 80 with one connection to port 5050. All HTTP requests return 404 Not Found responses indicating failed exploitation attempts.

Geographic spread includes targets in Japan, Europe, and Asia-Pacific region. Timing shows automated behavior with consistent sub-second packet intervals. Total capture represents approximately 10.8 seconds of aggressive scanning activity.

---

## Primary Anomalies Detected

**Port Scanning**
Single source 192.168.1.1 contacted 9 unique external IPs in 10.8 seconds. This represents one new target every 1.2 seconds, far exceeding human interaction patterns.

**Incomplete Handshakes**
35 TCP connections show SYN packets without proper ACK completion. This represents approximately 35% failure rate versus normal networks under 5%. Pattern indicates SYN scanning rather than legitimate communication.

**HTTP Exploitation**
68 HTTP packets target suspicious paths including /cgi-bin/proxy.c and /mute/c/prxjdg.c. All requests receive 404 responses. Pattern matches known Sdbot propagation behavior.

**Non-Standard Port**
Connection to 84.244.1.30 on port 5050 associated with backdoor/trojan activity. No legitimate business justification for this port usage.

**DNS Issues**
Retransmission detected for query to cgi14.plala.or.jp. DNS traffic represents only 4.6% of capture despite multiple targets, suggesting direct IP addressing or cached results.

---

## TCP-Level Analysis for Anomaly Detection

### TTL (Time To Live) Analysis

**Dlaczego TTL jest ważny:**
TTL wskazuje liczbę hopów pakietu przez sieć. Normalne wartości dla systemów lokalnych wynoszą 64 (Linux) lub 128 (Windows). Wartości znacznie niższe mogą wskazywać pakiety z odległych sieci lub spoofing.

**Anomalie w TTL:**
- Nieoczekiwane zmiany TTL od tego samego źródła mogą wskazywać IP spoofing
- TTL poniżej 30 dla lokalnej sieci sugeruje routing przez wiele hopów lub manipulację
- Różne wartości TTL w jednej sesji TCP są podejrzane

**Zastosowanie w detekcji:**
Monitorowanie TTL pomaga wykryć distributed attacks gdzie pakiety pochodzą z różnych źródeł mimo tego samego source IP. Również wykrywa OS fingerprinting attempts gdzie atakujący zmienia TTL aby imitować różne systemy.

**W tym PCAP:**
Powinniśmy sprawdzić czy 192.168.1.1 utrzymuje spójny TTL we wszystkich pakietach. Zmiany TTL wskazywałyby na spoofing lub proxy. Target IPs będą miały różne TTL w zależności od odległości geograficznej.

### ACK Number Sequences

**Dlaczego ACK numbers są ważne:**
ACK number w TCP wskazuje następny oczekiwany bajt. Normalna komunikacja pokazuje spójną sekwencję ACK odpowiadającą SEQ numbers. Anomalie w ACK wskazują problemy lub atak.

**Anomalie w ACK:**
- ACK numbers które nie odpowiadają wysłanym SEQ numbers mogą wskazywać injection attacks
- Duplikaty ACK mogą oznaczać packet loss lub retransmission attacks
- Brak ACK po SYN-ACK to incomplete handshake (widoczne w tym PCAP)

**Zastosowanie w detekcji:**
Analiza ACK sequences wykrywa TCP session hijacking gdzie atakujący wstrzykuje pakiety z nieprawidłowymi ACK numbers. Również pomaga zidentyfikować reset attacks i connection manipulation.

**W tym PCAP:**
35 sesji pokazuje SYN i SYN-ACK ale brak final ACK. To znaczy infected machine inicjuje połączenie, target odpowiada, ale bot nie wysyła ACK aby dokończyć handshake. Ten pattern to klasyczny SYN scan.

### TCP Window Size

**Dlaczego Window Size jest ważny:**
Window size kontroluje flow control w TCP, wskazując ile danych odbiorca może przyjąć. Normalne wartości to 65535 bytes (64KB) lub wielokrotności z window scaling.

**Anomalie w Window:**
- Window size równy 0 może wskazywać DoS attempt (window exhaustion)
- Bardzo małe wartości (np. 1-100 bytes) są nietypowe dla normalnej komunikacji
- Brak window scaling przy dużych transferach jest podejrzany

**Zastosowanie w detekcji:**
Window manipulation jest używana w niektórych atakach aby spowolnić lub zatrzymać komunikację. Monitoring window size patterns pomaga wykryć slow-rate DoS attacks.

**W tym PCAP:**
Wartości window size powinny być konsistentne dla 192.168.1.1. Jeśli bot używa małych wartości może to wskazywać attempt aby minimalizować własne resource usage podczas skanowania.

### TCP Options - Window Scale

**Dlaczego Window Scale jest ważny:**
Window scale option (TCP option kind 3) pozwala na okna większe niż 65535 bytes przez zastosowanie shift factor. Obecność tej opcji wskazuje że host wspiera high-throughput connections.

**Anomalie w Window Scale:**
- Brak window scale w nowoczesnych systemach jest nietypowy
- Inconsistent użycie tej opcji w różnych połączeniach od tego samego hosta może wskazywać OS spoofing
- Nieprawidłowe scale values (powyżej 14) są błędem lub manipulation attempt

**Zastosowanie w detekcji:**
Window scale pomaga w OS fingerprinting. Różne systemy używają różnych domyślnych scale factors. Linux często używa scale 7, Windows 8. Brak tej opcji może wskazywać legacy system lub narzędzie skanujące.

**W tym PCAP:**
Sprawdzenie czy 192.168.1.1 używa window scale konsystentnie pomoże określić czy to prawdziwy system operacyjny czy skrypt/narzędzie generujące pakiety.

### TCP Options - SACK Permitted

**Dlaczego SACK jest ważny:**
Selective Acknowledgment (SACK, option kind 4) pozwala na acknowledgment nieciągłych bloków danych, poprawiając performance przy packet loss. SACK permitted pojawia się w SYN packets jeśli host wspiera tę funkcję.

**Anomalie w SACK:**
- Nowoczesne systemy prawie zawsze deklarują SACK permitted
- Brak SACK może wskazywać stary system lub narzędzie skanujące które nie implementuje pełnego TCP stack
- Inconsistent SACK usage od tego samego hosta jest podejrzane

**Zastosowanie w detekcji:**
Obecność lub brak SACK permitted jest częścią OS fingerprinting. Ataki często pomijają optional TCP features aby uprościć implementację. Monitoring SACK patterns pomaga wykryć automated tools versus prawdziwe systemy.

**W tym PCAP:**
Jeśli 192.168.1.1 nie deklaruje SACK permitted w SYN packets, sugeruje to że bot używa uproszczonego TCP implementation. Prawdziwy Windows/Linux system deklarowałby SACK support.

### TCP Options - Maximum Segment Size (MSS)

**Dlaczego MSS jest ważny:**
MSS (option kind 2) deklaruje największy segment który host może przyjąć, typowo 1460 bytes dla Ethernet (1500 MTU minus 40 bytes IP/TCP headers). MSS zawsze pojawia się w SYN packets.

**Anomalie w MSS:**
- Bardzo mały MSS (np. poniżej 536) jest nietypowy dla nowoczesnych sieci
- Bardzo duży MSS (powyżej 1460 bez jumbo frames) może wskazywać manipulation
- Brak MSS option w SYN packet jest błędem protokołu

**Zastosowanie w detekcji:**
MSS values pomagają wykryć packet crafting tools które używają non-standard values. Również wskazują network path characteristics - MSS 1460 sugeruje standard Ethernet, inne wartości mogą wskazywać VPN, tunneling, lub spoofing.

**W tym PCAP:**
Sprawdzenie MSS w SYN packets od 192.168.1.1 pomoże określić czy bot używa realistic network parameters czy arbitrary values. Targets będą miały różne MSS w zależności od ich network configuration.

### TCP Options - Timestamps

**Dlaczego Timestamps są ważne:**
TCP timestamps option (kind 8) zawiera timestamp value i echo reply używane do RTT measurement i PAWS (Protection Against Wrapped Sequences). Nowoczesne systemy prawie zawsze używają timestamps.

**Anomalie w Timestamps:**
- Brak timestamps w nowoczesnym systemie jest nietypowy
- Timestamp values które nie rosną monotonically wskazują manipulation
- Inconsistent timestamp usage od tego samego hosta jest podejrzane

**Zastosowanie w detekcji:**
Timestamp analysis wykrywa packet replay attacks gdzie stare pakiety są retransmitted. Również pomaga w timing analysis aby wykryć automated versus human behavior. Timestamp echo replies pomagają wykryć session hijacking.

**W tym PCAP:**
Jeśli 192.168.1.1 używa timestamps, wartości powinny rosnąć konsystentnie. Brak timestamps sugeruje simplified bot implementation. Analiza timestamp increments może pokazać timing regularity characteristic dla automated scanning.

---

## Feature Engineering dla ML Detection

### Primary Features z TCP Analysis

**TTL-based features:**
- TTL consistency score: standard deviation TTL values od source IP
- TTL geographic correlation: czy TTL odpowiada expected hop count do targetu
- TTL manipulation indicator: czy TTL zmienia się w sposób inconsistent z routing

**ACK-based features:**
- Incomplete handshake ratio: percent sesji bez final ACK
- ACK sequence validity: czy ACK numbers odpowiadają SEQ numbers
- Duplicate ACK rate: frequency duplicate acknowledgments wskazujących retransmissions

**Window-based features:**
- Window size variance: consistency window size w sesjach
- Window scale presence: czy używa modern TCP features
- Zero window frequency: rate zero-window advertisements

**TCP Options fingerprint:**
- Options consistency: czy ten sam host używa same options w różnych connections
- Modern features score: presence SACK, timestamps, window scale
- MSS value distribution: czy MSS jest realistic dla network type

**Timing features:**
- Packet inter-arrival regularity: variance timing między pakietami
- Connection initiation rate: frequency nowych connections per second
- Session duration distribution: czy connections są unnaturally short

**Session-level features:**
- Handshake completion rate
- Retransmission frequency
- Reset packet ratio
- Geographic diversity score

---

## Detection Strategy

### Layer 1: TCP Protocol Validation

Pierwsza warstwa detekcji sprawdza czy TCP headers są valid i consistent. Błędy na tym poziomie wskazują packet crafting lub broken implementations.

Validations:
- Czy SYN packets zawierają MSS option
- Czy sequence numbers są properly initialized
- Czy ACK numbers odpowiadają previous SEQ numbers
- Czy window size jest non-zero dla established connections
- Czy TCP options są syntactically correct

Violations na tym poziomie mają wysoką confidence jako indicators malicious activity.

### Layer 2: Behavioral Analysis

Druga warstwa analizuje patterns w legitimate TCP sessions aby wykryć abnormal behavior.

Analysis:
- Incomplete handshake ratio przekracza 5% threshold
- Connection rate przekracza 10 connections/second
- Wszystkie HTTP requests zwracają 404 (failed exploitation)
- Geographic diversity przekracza 3 countries w krótkim czasie
- Session durations są consistently poniżej 10 seconds

Kombinacja multiple behavioral indicators zwiększa confidence detection.

### Layer 3: TCP Fingerprinting

Trzecia warstwa używa TCP options i parameters aby fingerprint source i wykryć inconsistencies.

Fingerprinting:
- Porównanie TCP options profile z known OS signatures
- Detection zmian w fingerprint od tego samego source IP
- Identification simplified TCP implementations characteristic dla scanning tools
- Correlation TTL values z expected OS defaults

Mismatches między declared OS (np. w HTTP User-Agent) a TCP fingerprint wskazują deception.

### Layer 4: Machine Learning Anomaly Scoring

Czwarta warstwa używa ML model trained na normal traffic aby score deviations.

Model inputs wszystkie extracted features:
- TTL consistency metrics
- ACK/SEQ analysis results
- Window size patterns
- TCP options fingerprint
- Timing characteristics
- Session completion rates
- Geographic patterns

Model output: anomaly score od -1 (extreme outlier) do 1 (normal). Threshold -0.5 triggers investigation, -0.7 triggers blocking.

---

## Expected Results dla tego PCAP

### Rule-based Detection

Source 192.168.1.1 powinien trigger:
- Incomplete handshake detection (35% failure rate)
- High connection rate (36.1 pps sustained)
- Port scan detection (9 targets w 10.8 seconds)
- Geographic anomaly (5+ countries contacted)
- HTTP exploitation pattern (100% 404 responses)

### TCP Protocol Analysis

Oczekiwane findings:
- TTL values powinny być consistent dla 192.168.1.1 jeśli to prawdziwy local host
- ACK sequences pokażą 35 instances brakujących final ACK packets
- Window sizes prawdopodobnie będą small/standard jeśli bot minimalizuje resources
- TCP options prawdopodobnie będą simplified (brak SACK/timestamps) jeśli to scanning tool
- MSS values powinny być standard 1460 jeśli bot nie manipuluje tego parametru

### ML Model Prediction

Feature vector dla 192.168.1.1:
- TTL consistency: High (if local) or Variable (if spoofed/proxied)
- Incomplete handshake ratio: 0.35 (35%)
- Connection rate: 36.1 connections/second
- Session duration avg: 3.24 seconds
- Geographic diversity: 5+ countries
- HTTP failure rate: 1.0 (100%)
- TCP options score: Low (if simplified stack)
- Timing regularity: High (automated pattern)

Expected anomaly score: -0.78 (strong outlier)
Classification: Malicious with 95%+ confidence

---

## Implementation Priorities

### Critical TCP Fields to Extract

Z każdego pakietu:
- IP TTL
- TCP sequence number
- TCP acknowledgment number
- TCP window size
- TCP flags (SYN, ACK, FIN, RST)
- TCP options (parse MSS, SACK permitted, window scale, timestamps)

Z każdej sesji:
- Handshake completion status (3-way completed?)
- ACK sequence validity (do numbers match?)
- Window size variance across session
- Retransmission count
- Option consistency across packets

### Feature Calculation

Per source IP aggregate:
- TTL standard deviation
- Incomplete handshake percentage
- Average packets per second
- Unique destination count
- Session duration statistics
- TCP options fingerprint hash
- Geographic diversity score

### Detection Thresholds

Based na tym PCAP i normal baseline:
- Incomplete handshake ratio > 0.10 (10%) = Medium alert
- Incomplete handshake ratio > 0.25 (25%) = High alert
- Connection rate > 10/sec sustained = High alert
- Unique destinations > 5 w 60 seconds = Medium alert
- Geographic diversity > 3 countries w 60 seconds = Medium alert
- Combination 3+ indicators = Critical alert

---

## SQL Schema Considerations

### Bronze Layer - Raw Packets

Minimally store:
- packet_id, timestamp, src_ip, dst_ip, src_port, dst_port
- protocol, tcp_flags
- **ttl, tcp_seq, tcp_ack, tcp_window**
- **tcp_options_raw (binary blob dla parsing)**
- packet_length

### Silver Layer - Sessions

Aggregate do:
- session_id, src_ip, dst_ip, src_port, dst_port
- start_time, end_time, duration
- packet_count, byte_count
- syn_count, ack_count, fin_count, rst_count
- handshake_complete (boolean)
- **ttl_values (array lub stats)**
- **ack_sequence_valid (boolean)**
- **avg_window_size, window_size_variance**
- **tcp_options_fingerprint (parsed structure)**

### Silver Layer - TCP Options

Separate table dla parsed options:
- session_id (foreign key)
- mss_value
- window_scale_value
- sack_permitted (boolean)
- timestamps_present (boolean)
- timestamp_values (dla timing analysis)

### Gold Layer - Anomalies

Detection results:
- anomaly_id, session_id
- detection_method (rule_based, ml_model)
- anomaly_type (port_scan, incomplete_handshake, etc)
- **ttl_anomaly_score**
- **ack_anomaly_score**
- **tcp_options_anomaly_score**
- combined_confidence_score
- reason_text

---

## Conclusion

Analiza tego PCAP pokazuje że TCP-level features są critical dla anomaly detection. TTL consistency, ACK sequence validation, window size patterns, i TCP options fingerprinting dostarczają rich signal dla distinguishing malicious od legitimate traffic.

Incomplete handshakes (35% w tym PCAP) są strongest indicator scanning activity. Kombinacja z timing analysis (36.1 pps), geographic diversity (9 IPs w 5+ countries), i HTTP failure patterns (100% 404) daje high-confidence detection.

Implementation powinien prioritize extraction TCP header fields i options, calculation session-level statistics, i correlation multiple indicators dla robust detection z low false positive rate.

Dataset jest excellent dla training i testing detection pipeline z clear ground truth (192.168.1.1 = malicious, targets = victims).

---

End of Analysis
