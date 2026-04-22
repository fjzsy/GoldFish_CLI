#include "commconfig.h"
#include <iostream>
#include <QDir>
#include <QFileInfo>
#include <QDirIterator>

CommConfig::CommConfig() {}

void CommConfig::print_help()
{

std::cout << R"(
===============================================================================
GoldFish-CLI - RoCEv2 Network Protocol Analyzer
===============================================================================

Usage:
  Single file mode:   GoldFish-CLI -f <FILE> [OPTIONS]
  Batch mode:         GoldFish-CLI -d <DIR> [OPTIONS]

===============================================================================
Input Options (mutually exclusive)
===============================================================================
  -f, --file <FILE>          Analyze a single PCAP file
  -d, --dir <DIR>            Batch analyze all PCAP files in directory

===============================================================================
Batch Mode Options (only with -d)
===============================================================================
  -r, --recursive            Recursively search subdirectories
  -e, --ext <ext>            File extensions (default: .pcap,.pcapng)
                             Example: -e .pcap,.cap

===============================================================================
Output Options
===============================================================================
  -o, --output <PATH>        Output file or directory path
                             Single file mode: output to file
                             Batch mode with file: merged output
                             Batch mode with directory: individual files
  -s, --stats-only           Print summary statistics only
  -l, --limit <N>            Limit number of flows in output (default: unlimited)

===============================================================================
Other Options
===============================================================================
  -t, --threshold <PCT>      Packet loss alert threshold (default: 0.1%)
  -v, --verbose              Verbose output (show progress)
  -q, --quiet                Quiet mode (errors only)
  -h, --help                 Show this help message
  -V, --version              Show version information

===============================================================================
Examples
===============================================================================

  # Single file analysis
  GoldFish-CLI -f capture.pcap
  GoldFish-CLI -f capture.pcap -o report.txt
  GoldFish-CLI -f capture.pcap -f json -o report.json
  GoldFish-CLI -f capture.pcap -s -v

  # Batch directory analysis
  GoldFish-CLI -d /path/to/pcaps/
  GoldFish-CLI -d /path/to/pcaps/ -r -v
  GoldFish-CLI -d /path/to/pcaps/ -e .pcap,.cap
  GoldFish-CLI -d /path/to/pcaps/ -o summary.txt
  GoldFish-CLI -d /path/to/pcaps/ -o ./reports/ -f json

  # Advanced options
  GoldFish-CLI -f capture.pcap -l 20 -t 0.05
  GoldFish-CLI -d ./pcaps/ -s -l 10

===============================================================================
Exit Codes
===============================================================================
  0   Success
  1   Invalid argument
  2   Input file/directory not found
  3   Permission denied (cannot read input or write output)
  4   Unsupported file format (only .pcap, .pcapng)
  5   PCAP parsing failed (corrupted file)
  6   Out of memory
  7   Output write failed
  8   Unknown error

===============================================================================
)" << std::endl;
}

void CommConfig::print_version()
{
    std::cout << R"(
GoldFish-CLI version 1.0.0
RoCEv2 Network Protocol Analyzer

Copyright (c) 2026 GoldFish Developer
License: Apache 2.0 / MIT

Features:
  - RoCEv2 packet parsing (OpCode, PSN, QP)
  - 5-tuple flow aggregation
  - Packet loss, retransmission, out-of-order detection
  - PSN sequence analysis
  - Multiple output formats: text, csv, json
  - Single file and batch directory processing

Built with: C++17, libpcap, Qt5/6
)" << std::endl;
}

int CommConfig::parse_arguments(int argc, char *argv[], Config &cfg)
{
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_help();
            exit(0);
        }

        if (arg == "-V" || arg == "--version") {
            print_version();
            exit(0);
        }

        if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) {
                std::cerr << "ERROR: -f/--file requires an argument" << std::endl;
                return 1;
            }
            if (cfg.mode != Config::MODE_NONE) {
                std::cerr << "ERROR: Cannot specify both -f and -d" << std::endl;
                return 1;
            }
            cfg.mode = Config::MODE_FILE;
            cfg.input_path = argv[++i];
        }
        else if (arg == "-d" || arg == "--dir") {
            if (i + 1 >= argc) {
                std::cerr << "ERROR: -d/--dir requires an argument" << std::endl;
                return 1;
            }
            if (cfg.mode != Config::MODE_NONE) {
                std::cerr << "ERROR: Cannot specify both -f and -d" << std::endl;
                return 1;
            }
            cfg.mode = Config::MODE_DIR;
            cfg.input_path = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "ERROR: -o/--output requires an argument" << std::endl;
                return 1;
            }
            cfg.output_path = argv[++i];
        }
        // else if (arg == "-f" || arg == "--format") {
        //     if (i + 1 >= argc) {
        //         std::cerr << "ERROR: -f/--format requires an argument" << std::endl;
        //         return 1;
        //     }
        //     cfg.format = argv[++i];
        //     if (cfg.format != "text" && cfg.format != "csv" && cfg.format != "json") {
        //         std::cerr << "ERROR: Invalid format. Supported: text, csv, json" << std::endl;
        //         return 1;
        //     }
        // }
        // else if (arg == "-s" || arg == "--stats-only") {
        //     cfg.stats_only = true;
        // }
        // else if (arg == "-l" || arg == "--limit") {
        //     if (i + 1 >= argc) {
        //         std::cerr << "ERROR: -l/--limit requires an argument" << std::endl;
        //         return 1;
        //     }
        //     cfg.limit = std::stoi(argv[++i]);
        //     if (cfg.limit <= 0) {
        //         std::cerr << "ERROR: Limit must be positive" << std::endl;
        //         return 1;
        //     }
        // }
        // else if (arg == "-r" || arg == "--recursive") {
        //     cfg.recursive = true;
        // }
        else if (arg == "-e" || arg == "--ext") {
            if (i + 1 >= argc) {
                std::cerr << "ERROR: -e/--ext requires an argument" << std::endl;
                return 1;
            }
            std::string ext_str = argv[++i];
            cfg.extensions.clear();
            size_t pos = 0;
            while ((pos = ext_str.find(',')) != std::string::npos) {
                std::string ext = ext_str.substr(0, pos);
                if (!ext.empty()) cfg.extensions.push_back(QString::fromStdString(ext));
                ext_str.erase(0, pos + 1);
            }
            if (!ext_str.empty()) cfg.extensions.push_back(QString::fromStdString(ext_str));
        }
        else if (arg == "-t" || arg == "--threshold") {
            if (i + 1 >= argc) {
                std::cerr << "ERROR: -t/--threshold requires an argument" << std::endl;
                return 1;
            }
            cfg.threshold = std::stod(argv[++i]);
            if (cfg.threshold < 0 || cfg.threshold > 100) {
                std::cerr << "ERROR: Threshold must be between 0 and 100" << std::endl;
                return 1;
            }
        }
        else if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
            cfg.quiet = false;
        }
        else if (arg == "-q" || arg == "--quiet") {
            cfg.quiet = true;
            cfg.verbose = false;
        }
        else {
            std::cerr << "ERROR: Unknown option: " << arg << std::endl;
            std::cerr << "Run with -h for help" << std::endl;
            return 1;
        }
    }

    // 验证必需参数
    if (cfg.mode == Config::MODE_NONE) {
        std::cerr << "ERROR: Must specify either -f/--file or -d/--dir" << std::endl;
        std::cerr << "Run with -h for help" << std::endl;
        return 1;
    }

    if (cfg.mode == Config::MODE_DIR && cfg.recursive && cfg.extensions.empty()) {
        std::cerr << "ERROR: -r/--recursive requires -e/--ext" << std::endl;
        return 1;
    }

    return 0;
}

int CommConfig::validate_input(const Config &cfg)
{
    // 单文件模式
    if (cfg.mode == Config::MODE_FILE) {
        QFile file(cfg.input_path);

        // 检查文件是否存在
        if (!file.exists()) {
            std::cerr << "ERROR: Input file '" << cfg.input_path.toStdString() << "' does not exist" << std::endl;
            return 2;
        }

        // 检查文件是否可读
        if (!file.open(QIODevice::ReadOnly)) {
            std::cerr << "ERROR: Cannot read input file '" << cfg.input_path.toStdString() << "'" << std::endl;
            std::cerr << "Reason: Permission denied or file is locked" << std::endl;
            return 3;
        }
        file.close();

        // 检查文件扩展名
        QFileInfo fileInfo(file);
        QString suffix = fileInfo.suffix().toLower();
        if (suffix != "pcap" && suffix != "pcapng") {
            std::cerr << "ERROR: Unsupported file format '" << suffix.toStdString()
            << "'. Only .pcap and .pcapng are supported" << std::endl;
            return 4;
        }
    }
    // 批量目录模式
    else if (cfg.mode == Config::MODE_DIR) {
        QDir dir(QString::fromStdString(cfg.input_path.toStdString()));

        // 检查目录是否存在
        if (!dir.exists()) {
            std::cerr << "ERROR: Directory '" << cfg.input_path.toStdString() << "' does not exist" << std::endl;
            return 2;
        }

        // 检查目录是否可读
        if (!dir.isReadable()) {
            std::cerr << "ERROR: Cannot read directory '" << cfg.input_path.toStdString() << "'" << std::endl;
            std::cerr << "Reason: Permission denied" << std::endl;
            return 3;
        }
    }

    return 0;
}

QList<QString> CommConfig::scan_pcap_files(const QString& dirPath, bool recursive)
{
    QList<QString> files;

    QStringList nameFilters;
    nameFilters << "*.pcap" << "*.pcapng";

    QDirIterator::IteratorFlags flags = QDirIterator::NoIteratorFlags;
    if (recursive) {
        flags = QDirIterator::Subdirectories;
    }

    // 使用正确的构造函数
    QDirIterator it(dirPath, nameFilters, QDir::Files, flags);

    while (it.hasNext()) {
        it.next();
        files.push_back(it.filePath());

        // 调试输出
        // qDebug() << "Found:" << it.filePath();
    }

    return files;
}


QString CommConfig::generate_output_path(const Config &config, const QString &input_file)
{
    if (config.output_path.isEmpty()) {
        return "";
    }

    QFileInfo outputInfo(config.output_path);

    if (outputInfo.isDir() || config.output_path.back() == '/' || config.output_path.back() == '\\') {
        QFileInfo inputInfo(input_file);
        QString baseName = inputInfo.completeBaseName();
        QString ext;
        if (config.format == "json") ext = ".json";
        else if (config.format == "csv") ext = ".csv";
        else ext = ".txt";

        QDir dir(config.output_path);
        if (!dir.exists()) dir.mkpath(".");

        return dir.filePath(baseName + ext);
    }

    return config.output_path;
}
