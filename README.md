# GoldFish-CLI

**RoCEv2 Network Protocol Analyzer for High-Performance Networking Debugging**

GoldFish-CLI is a lightweight, high-performance command-line tool for analyzing RoCEv2 (RDMA over Converged Ethernet) traffic. It parses PCAP files, extracts RoCEv2 protocol information, aggregates flows by 5-tuple + QP, and detects packet loss, retransmission, and out-of-order issues.

## Features

- **RoCEv2 Protocol Parsing** - Extracts OpCode, PSN (Packet Sequence Number), QP (Queue Pair), and other RDMA headers
- **Flow Aggregation** - Groups packets by 5-tuple (src/dst IP, src/dst port) + QP
- **Loss & Retransmission Detection** - Identifies packet loss and retransmission through PSN sequence analysis
- **Out-of-Order Detection** - Detects out-of-order packets in the PSN sequence
- **Multiple Output Formats** - Supports text, CSV, and JSON output
- **Single File & Batch Mode** - Analyze a single PCAP or recursively process entire directories
- **Flexible Filtering** - Limit output flows, set loss threshold alerts
- **Cross-Platform** - Works on Linux (primary), Windows, and macOS

## Quick Start

```bash
# Clone the repository
git clone https://github.com/fjzsy/GoldFish-CLI.git
cd GoldFish-CLI

# Build
mkdir build && cd build
cmake .. && make

# Run a quick analysis
./GoldFish-CLI -f sample.pcap
Usage
Command Line Options
Option	Description
-f, --file <FILE>	Analyze a single PCAP file
-d, --dir <DIR>	Batch analyze all PCAP files in directory
-r, --recursive	Recursively search subdirectories (with -d)
-e, --ext <ext>	File extensions (default: .pcap,.pcapng)
-o, --output <PATH>	Output file or directory path
-t, --threshold <PCT>	Packet loss alert threshold (default: 0.1%)
-v, --verbose	Verbose output (show progress)
-q, --quiet	Quiet mode (errors only)
-h, --help	Show help message
-V, --version	Show version information
Examples
bash
# Single file analysis
./GoldFish-CLI -f capture.pcap

# Single file with JSON output
./GoldFish-CLI -f capture.pcap -F json -o report.json

# Batch process all PCAP files in directory
./GoldFish-CLI -d ./pcaps/

# Recursive batch processing with custom extension
./GoldFish-CLI -d ./pcaps/ -r -e .pcap

# Batch processing with summary only and flow limit
./GoldFish-CLI -d ./pcaps/ -s -l 20

# Set loss threshold alert (alert if loss > 0.05%)
./GoldFish-CLI -f capture.pcap -t 0.05 -v
Output Examples
Text Format
text
===========================================================================
RoCEv2 Flow Statistics
===========================================================================
Source IP       SrcPort  Dest IP         DestPort  QP  OpCode  Packets  Loss%
192.168.1.10    12345    192.168.1.20    4791      88  0x02    10000    0.00
192.168.1.20    4791     192.168.1.10    12345     88  0x11    10000    0.00
...
===========================================================================
Summary:
  Total Packets: 50000
  Total RoCEv2 Packets: 49950
  Total Flows: 8
  Overall Loss Rate: 0.02%
===========================================================================
CSV Format (compatible with Excel)
csv
SrcIP,SrcPort,DstIP,DstPort,QP,OpCode,Packets,LossRate,AvgDelay(us)
192.168.1.10,12345,192.168.1.20,4791,88,0x02,10000,0.00,12.3
192.168.1.20,4791,192.168.1.10,12345,88,0x11,10000,0.00,15.7
JSON Format (for programmatic use)
json
{
  "summary": {
    "total_packets": 50000,
    "total_roce_packets": 49950,
    "total_flows": 8,
    "overall_loss_rate": 0.02
  },
  "flows": [
    {
      "src_ip": "192.168.1.10",
      "src_port": 12345,
      "dst_ip": "192.168.1.20",
      "dst_port": 4791,
      "qp": 88,
      "opcode": "0x02",
      "packets": 10000,
      "loss_rate": 0.00,
      "avg_delay_us": 12.3
    }
  ]
}
Use Cases
RDMA Network Debugging - Quickly identify which flows are experiencing packet loss or retransmission

Performance Testing - Verify RoCEv2 network performance under different workloads

CI/CD Integration - Integrate into automated testing pipelines for network validation

Batch Analysis - Process hundreds of PCAP files from long-term monitoring

Dependencies
CMake 3.16+

C++17 compatible compiler (GCC 9+, Clang 10+, MSVC 2019+)

libpcap (Linux) / WinPcap (Windows)

Qt5 Core (for command-line parsing only, no GUI)

Building from Source
Ubuntu / Debian
bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev qt5-qmake qtbase5-dev

# Build
git clone https://github.com/fjzsy/GoldFish-CLI.git
cd GoldFish-CLI
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run
./GoldFish-CLI -h
CentOS / RHEL / Fedora
bash
# Install dependencies
sudo yum install -y cmake gcc-c++ libpcap-devel qt5-qtbase-devel

# Build (same as above)
git clone https://github.com/fjzsy/GoldFish-CLI.git
cd GoldFish-CLI
mkdir build && cd build
cmake ..
make -j$(nproc)
Windows (MSYS2 / MinGW)
bash
# Install MSYS2, then install dependencies
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-libpcap mingw-w64-x86_64-qt5

# Build
git clone https://github.com/fjzsy/GoldFish-CLI.git
cd GoldFish-CLI
mkdir build && cd build
cmake .. -G "MinGW Makefiles"
mingw32-make
Project Structure
text
GoldFish-CLI/
├── src/
│   ├── main.cpp                  # Main entry point, CLI parsing
│   ├── pcapfilereader.cpp/h      # PCAP file reading
│   ├── protocol_parsers.cpp/h    # RoCEv2 protocol parsing
│   ├── flowaggregator.cpp/h      # Flow aggregation logic
│   ├── analytics.cpp/h           # PSN sequence analysis
│   ├── reportdata.cpp/h          # Report generation
│   └── ...                       # Additional modules
├── CMakeLists.txt                # CMake build configuration
├── README.md                     # This file
└── docs/                         # Detailed documentation
Performance
Processes 75,000 packets in ~40ms on a modern CPU

Handles PCAP files up to 2GB (memory permitting)

Batch mode can process thousands of files efficiently

Limitations
Only analyzes RoCEv2 packets (UDP port 4791). Other RoCE versions are not supported.

Does not perform real-time capture; works with offline PCAP files only.

No GUI; command-line only (the GUI version is a separate commercial product).

Author
Independent Developer - Specializing in C++/Qt, embedded Linux, high-performance networking, and video streaming (GStreamer/RK3588).

GitHub: fjzsy

Project: GoldFish-CLI

License
Apache License 2.0 - You may use, modify, and distribute this software freely, provided you retain the copyright notice and disclaimer.

Contributing
Issues, feature requests, and pull requests are welcome! Feel free to:

Report bugs via GitHub Issues

Suggest features or improvements

Submit pull requests with fixes or enhancements

Related Projects
GoldFish-GUI (Commercial) - Graphical interface with real-time timing diagrams, advanced visualization, and one-click report generation (coming soon).

GoldFish-CLI - Making RoCEv2 network debugging faster and easier.