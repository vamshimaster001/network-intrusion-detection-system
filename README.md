MULTI-THREADED HTTP INTRUSION DETECTION SYSTEM (IDS)
====================================================

OVERVIEW
--------
A high-performance Intrusion Detection System (IDS) written in C using Linux raw sockets.
The project captures live network traffic, parses HTTP requests, performs regex-based
attack detection, and generates structured JSON alerts.

FEATURES
--------
1. Raw socket packet capture (AF_PACKET)
2. Multi-threaded producer-consumer architecture
3. HTTP request parsing
4. Regex-based rule engine
5. Threshold-based alert suppression
6. Port scan detection
7. JSON alert logging
8. Atomic counters using C11 atomics

DETECTION CAPABILITIES
----------------------
- SQL Injection Detection
- XSS Detection
- Directory Traversal Detection
- Command Injection Detection
- Custom Regex Rules

ARCHITECTURE
------------
Network Interface
        ↓
AF_PACKET Raw Socket
        ↓
Capture Thread (Producer)
        ↓
Packet Queue
        ↓
Worker Threads (Consumers)
        ↓
HTTP Parser
        ↓
Regex Detection Engine
        ↓
Alert Generation
        ↓
JSON Logging

TECHNOLOGIES USED
-----------------
- C11
- POSIX Threads
- Linux Raw Sockets
- POSIX Regex
- Condition Variables
- Atomic Operations
- JSON Logging

BUILD
-----
gcc -std=c11 ids.c -o ids -pthread

RUN
---
sudo ./ids

TESTING
-------
curl http://localhost
nmap -p 1-100 localhost

CONCEPTS DEMONSTRATED
---------------------
- Linux networking stack
- Ethernet/IP/TCP parsing
- Raw socket programming
- Multi-threaded systems programming
- Producer-consumer design pattern
- Thread synchronization
- Signature-based IDS design
- Behavioral detection techniques

FUTURE IMPROVEMENTS
-------------------
- Offline PCAP analysis
- SYN flood detection
- eBPF integration
- DPDK packet processing
- Netfilter kernel integration
- Rule hot reloading
- Web dashboard
