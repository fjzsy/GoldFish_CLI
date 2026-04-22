GoldFish-CLI - Source File Structure and Documentation
Project Overview
GoldFish-CLI is a command-line tool for analyzing RoCEv2 (RDMA over Converged Ethernet) network traffic. It parses PCAP files, extracts RoCEv2 protocol information, aggregates flows, and detects packet loss, retransmission, and out-of-order issues.

Source File Structure
text
GoldFish-CLI/
├── src/
│   ├── main.cpp                    # Main entry point, command-line parsing
│   ├── pcap_reader.cpp/h           # PCAP file reading and packet parsing
│   ├── roce_parser.cpp/h           # RoCEv2 protocol parsing (BTH, IB headers)
│   ├── flow_aggregator.cpp/h       # 5-tuple + QP flow aggregation
│   ├── psn_analyzer.cpp/h          # PSN sequence analysis, loss/retrans detection
│   ├── report_generator.cpp/h      # Report generation (text/csv/json)
│   └── utils.cpp/h                 # Helper functions (timestamp, checksum)
├── include/                        # Public headers
├── CMakeLists.txt                  # CMake build configuration
└── README.md                       # Project documentation
Source File Descriptions
1. main.cpp - Main Entry Point
Purpose: Command-line interface, argument parsing, and overall workflow orchestration.

Key Functions:

main(): Entry point, parses arguments, selects single-file or batch mode

parse_arguments(): Processes command-line options using Qt's QCommandLineParser

validate_input(): Checks if input file/directory exists and is readable

scan_pcap_files(): Recursively scans directory for PCAP files

analyze_single_file(): Orchestrates analysis for one PCAP file

Supported Arguments:

text
-f, --file <FILE>      Analyze single PCAP file
-d, --dir <DIR>        Batch analyze all PCAP files in directory
-r, --recursive        Recursively search subdirectories
-e, --ext <ext>        File extensions (default: .pcap,.pcapng)
-o, --output <PATH>    Output file or directory path
-f, --format <FORMAT>  Output format: text, csv, json
-s, --stats-only       Print summary statistics only
-l, --limit <N>        Limit number of flows
-t, --threshold <PCT>  Packet loss alert threshold
-v, --verbose          Verbose output
-q, --quiet            Quiet mode (errors only)
2. pcap_reader.cpp/h - PCAP File Reader
Purpose: Read PCAP files and extract raw Ethernet frames.

Key Classes/Functions:

PcapReader: Main class for PCAP operations

open(): Open PCAP file

read_next_packet(): Read next packet header and data

get_packet_count(): Return total packet count

get_timestamp(): Get packet timestamp (microseconds)

Dependencies: libpcap (or WinPcap/Npcap on Windows)

Data Structures:

cpp
struct PacketInfo {
    uint64_t timestamp_us;   // Microsecond timestamp
    uint32_t caplen;         // Captured length
    uint32_t len;            // Original length
    const uint8_t* data;     // Raw packet data
};
3. roce_parser.cpp/h - RoCEv2 Protocol Parser
Purpose: Parse RoCEv2 packets and extract RDMA headers.

Key Functions:

is_rocev2_packet(): Check if UDP packet is RoCEv2 (dst port 4791)

parse_rocev2_header(): Parse BTH (Base Transport Header)

extract_opcode(): Extract OpCode (SEND/WRITE/READ/ACK)

extract_psn(): Extract Packet Sequence Number (24-bit)

extract_qp(): Extract Queue Pair number

extract_sip_dip(): Extract source/destination IP addresses

extract_ports(): Extract UDP source/destination ports

RoCEv2 Header Structure:

text
+--------+--------+--------+--------+
| BTH    | IETH   | Payload         |
+--------+--------+-----------------+
BTH: 12 bytes (OpCode, PSN, QP, etc.)
IETH: optional (RETH/AtomicETH/AETH)
OpCode Values:

cpp
enum OpCode {
    SEND_FIRST      = 0x00,
    SEND_MIDDLE     = 0x01,
    SEND_LAST       = 0x02,
    SEND_ONLY       = 0x04,
    WRITE_FIRST     = 0x06,
    WRITE_LAST      = 0x07,
    WRITE_ONLY      = 0x08,
    READ_REQ        = 0x0C,
    READ_RESP_FIRST = 0x11,
    READ_RESP_LAST  = 0x12,
    READ_RESP_ONLY  = 0x13,
    ACK             = 0x80,
    NAK             = 0x81
};
4. flow_aggregator.cpp/h - Flow Aggregator
Purpose: Group packets into flows based on 5-tuple + QP.

Key Classes/Functions:

FlowAggregator: Main class

add_packet(): Add packet to flow aggregation

get_flows(): Return all aggregated flows

get_flow_count(): Return number of unique flows

Flow Key Structure:

cpp
struct FlowKey {
    uint32_t src_ip;      // Source IP address
    uint32_t dst_ip;      // Destination IP address
    uint16_t src_port;    // Source UDP port
    uint16_t dst_port;    // Destination UDP port (usually 4791)
    uint32_t qp;          // Queue Pair number
};
Flow Statistics Structure:

cpp
struct FlowStats {
    FlowKey key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t first_psn;
    uint64_t last_psn;
    uint64_t max_psn;
    uint64_t retrans_count;
    uint64_t lost_packets;
    double loss_rate;
    // ... timing fields
};
5. psn_analyzer.cpp/h - PSN Sequence Analyzer
Purpose: Analyze PSN sequences to detect packet loss, retransmission, and out-of-order.

Key Classes/Functions:

PSNAnalyzer: Main class

add_psn(): Add PSN value to sequence

detect_loss(): Detect missing PSNs

detect_retrans(): Detect duplicate PSNs

detect_oos(): Detect out-of-order packets

get_loss_count(): Return total lost packets

get_retrans_count(): Return total retransmissions

get_psn_sequence(): Return full PSN sequence

Algorithm:

Maintain expected PSN based on normal step size (usually +1)

Detect jump > step → packet loss

Detect same PSN twice → retransmission

Detect PSN < previous (non-wraparound) → out-of-order

PSN Wraparound Handling:

PSN is 24-bit (0x000000 - 0xFFFFFF)

Detect wraparound when current PSN < previous PSN and difference > threshold

6. report_generator.cpp/h - Report Generator
Purpose: Generate analysis reports in various formats.

Key Functions:

generate_text_report(): Generate human-readable text report

generate_csv_report(): Generate CSV for spreadsheet analysis

generate_json_report(): Generate JSON for programmatic use

print_flow_table(): Print flow statistics table

print_summary(): Print summary statistics

Output Formats:

Text Format:

text
===========================================================================
RoCEv2 Flow Statistics
===========================================================================
SrcIP            SrcPort DstIP            DstPort QP   OpCode Pkts  Loss%
192.168.1.1      12345   192.168.1.2      4791    88   0x02   1000  0.00
...
===========================================================================
Summary:
  Total Packets: 100000
  Total RoCEv2 Packets: 99900
  Total Flows: 10
  Total Loss Rate: 0.05%
===========================================================================
CSV Format:

csv
SrcIP,SrcPort,DstIP,DstPort,QP,OpCode,Packets,LossRate,AvgDelay
192.168.1.1,12345,192.168.1.2,4791,88,0x02,1000,0.00,12.3
JSON Format:

json
{
  "summary": {
    "total_packets": 100000,
    "total_roce_packets": 99900,
    "total_flows": 10,
    "overall_loss_rate": 0.05
  },
  "flows": [
    {
      "src_ip": "192.168.1.1",
      "src_port": 12345,
      "dst_ip": "192.168.1.2",
      "dst_port": 4791,
      "qp": 88,
      "opcode": "0x02",
      "packets": 1000,
      "loss_rate": 0.00
    }
  ]
}
7. utils.cpp/h - Utility Functions
Purpose: Common helper functions used across modules.

Key Functions:

ip_to_string(): Convert uint32_t IP to dotted string

string_to_ip(): Convert dotted string to uint32_t IP

timestamp_to_string(): Convert timestamp to readable format

get_current_time_ms(): Get current time in milliseconds

calculate_loss_rate(): Calculate loss percentage

is_valid_pcap(): Check if file is valid PCAP format

Build Instructions
bash
# Clone repository
git clone https://github.com/fjzsy/GoldFish-CLI.git
cd GoldFish-CLI

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build
make

# Run
./GoldFish-CLI -f sample.pcap
Dependencies
CMake 3.16+

C++17 compatible compiler

libpcap (Linux) / WinPcap/Npcap (Windows)

Qt5 Core (for command-line parsing)

License
Apache 2.0

This documentation should help users understand your source code structure and quickly get started with GoldFish-CLI.