```
# TCP Tracer Program README

## Introduction

The TCP Tracer program is a Python script that analyzes network packet captures in PCAP format and provides statistics and details about TCP connections found in the trace. This README provides instructions on how to execute the program and how to interpret the generated output.

## Requirements

- Python 3.x
- PCAP packet capture file (e.g., .cap format)

## Usage

Execute the program with the following command:

```bash
python3 tcp_tracer.py <tracefile>.cap
```

Replace `<tracefile>.cap` with the path to your PCAP capture file.

## Output Analysis

The program provides the following sections of output:

### A) Total Number of Connections

This section provides the total number of connections found in the trace.

### B) Connection Details

For each connection found, detailed information is displayed, including source and destination addresses, ports, status, and connection-related statistics. The following statistics are included:
- Number of reset connections
- Number of open connections
- Number of complete connections
- Duration of the connection
- Minimum, mean, and maximum Round-Trip Time (RTT)
- Minimum, mean, and maximum number of packets
- Minimum, mean, and maximum received window size

### C) General

This section provides a summary of general statistics, including the total number of complete TCP connections, the number of reset TCP connections, and the number of TCP connections that were still open when the trace capture ended.

### D) Complete TCP Connections

This section provides statistics related to complete TCP connections, including minimum, mean, and maximum time duration, RTT values, the number of packets, and received window sizes.
