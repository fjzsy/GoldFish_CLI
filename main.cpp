#include "commconfig.h"
#include "pcapfilereader.h"
#include "reportdata.h"
#include <QCoreApplication>
#include <QLocale>
#include <iostream>
#include "pcapanalyzerapp.h"
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QDebug>

PcapAnalyzerApp analyzer;
PcapFileReader pcapReader;
FlowAggregator aggregator;
ReportData report;
QString fileName;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    a.setApplicationName("GoldFish-CLI");
    a.setApplicationVersion("1.0.0");

    // report.setPcapFileName(fileName);//传递被分析数据包文件名
    // app.analyzePcapFile(fileName.toStdString(), &report);//协议分析
    // //输出报表文件
    // report.saveToFile();

    // ========== 命令行参数解析 ==========
    QCommandLineParser parser;
    parser.setApplicationDescription("RoCEv2 Network Protocol Analyzer");
    parser.addHelpOption();
    parser.addVersionOption();

    // 输入选项（互斥）
    QCommandLineOption fileOption(QStringList() << "f" << "file",
                                  "Analyze a single PCAP file", "file");
    QCommandLineOption dirOption(QStringList() << "d" << "dir",
                                 "Batch analyze all PCAP files in directory", "dir");
    parser.addOption(fileOption);
    parser.addOption(dirOption);

    // 输出选项
    QCommandLineOption outputOption(QStringList() << "o" << "output",
                                    "Output file path", "file");
    QCommandLineOption formatOption(QStringList() << "f" << "format",
                                    "Output format: text, csv, json (default: text)", "format");
    QCommandLineOption statsOnlyOption(QStringList() << "s" << "stats-only",
                                       "Print summary statistics only");
    QCommandLineOption limitOption(QStringList() << "l" << "limit",
                                   "Limit number of flows", "number");
    parser.addOption(outputOption);
    parser.addOption(formatOption);
    parser.addOption(statsOnlyOption);
    parser.addOption(limitOption);

    // 批量模式选项
    QCommandLineOption recursiveOption(QStringList() << "r" << "recursive",
                                       "Recursively search subdirectories");
    QCommandLineOption extOption(QStringList() << "e" << "ext",
                                 "File extensions (default: .pcap,.pcapng)", "ext");
    parser.addOption(recursiveOption);
    parser.addOption(extOption);

    // 其他选项
    QCommandLineOption thresholdOption(QStringList() << "t" << "threshold",
                                       "Packet loss alert threshold (default: 0.1)", "percent");
    QCommandLineOption verboseOption(QStringList() << "v" << "verbose",
                                     "Verbose output");
    QCommandLineOption quietOption(QStringList() << "q" << "quiet",
                                   "Quiet mode (errors only)");
    parser.addOption(thresholdOption);
    parser.addOption(verboseOption);
    parser.addOption(quietOption);

    // 解析参数
    parser.process(a);

    // ========== 验证参数 ==========
    bool hasFile = parser.isSet(fileOption);
    bool hasDir = parser.isSet(dirOption);

    if (!hasFile && !hasDir) {
        std::cerr << "ERROR: Must specify either -f/--file or -d/--dir" << std::endl;
        parser.showHelp(1);
        return 1;
    }

    if (hasFile && hasDir) {
        std::cerr << "ERROR: Cannot specify both -f and -d" << std::endl;
        parser.showHelp(1);
        return 1;
    }

    // ========== 获取参数值 ==========
    Config config;
    config.verbose = parser.isSet(verboseOption);
    config.quiet = parser.isSet(quietOption);

    if (hasFile) {
        config.mode = Config::MODE_FILE;
        config.input_path = parser.value(fileOption);
    } else {
        config.mode = Config::MODE_DIR;
        config.input_path = parser.value(dirOption);
        config.recursive = parser.isSet(recursiveOption);

        if (parser.isSet(extOption)) {
            config.extensions.clear();
            QString extStr = parser.value(extOption);
            for (const QString& ext : extStr.split(',')) {
                config.extensions.push_back(ext);
            }
        }
    }

    // if (parser.isSet(outputOption)) {
    //     config.output_path = parser.value(outputOption);
    // }

    // if (parser.isSet(formatOption)) {
    //     config.format = parser.value(formatOption);
    //     if (config.format != "text" && config.format != "csv" && config.format != "json") {
    //         std::cerr << "ERROR: Invalid format. Supported: text, csv, json" << std::endl;
    //         return 1;
    //     }
    // }

    // if (parser.isSet(limitOption)) {
    //     config.limit = parser.value(limitOption).toInt();
    //     if (config.limit <= 0) {
    //         std::cerr << "ERROR: Limit must be positive" << std::endl;
    //         return 1;
    //     }
    // }

    // config.stats_only = parser.isSet(statsOnlyOption);

    // if (parser.isSet(thresholdOption)) {
    //     config.threshold = parser.value(thresholdOption).toDouble();
    //     if (config.threshold < 0 || config.threshold > 100) {
    //         std::cerr << "ERROR: Threshold must be between 0 and 100" << std::endl;
    //         return 1;
    //     }
    // }

    // ========== 验证输入文件/目录 ==========
    CommConfig cfgCheck;
    int ret = cfgCheck.validate_input(config);
    if (ret != 0) {
        return ret;
    }

    analyzer.setPcapReader(&pcapReader);
    analyzer.setAggregator(&aggregator);
    pcapReader.setAggregator(&aggregator);

    // ========== 执行分析 ==========
    try {
        if (config.mode == Config::MODE_FILE) {
            // 单文件模式
            report.setPcapFileName(config.input_path);

            if (config.verbose) {
                std::cout << "Analyzing: " << config.input_path.toStdString() << std::endl;
            }

            analyzer.analyzePcapFile(config.input_path.toStdString(), &report);
            report.saveToFile();

        } else {
            // 批量目录模式
            auto files = cfgCheck.scan_pcap_files(config.input_path);

            if (files.empty()) {
                std::cerr << "WARNING: No PCAP files found in '"
                          << config.input_path.toStdString() << "'" << std::endl;
                return 0;
            }

            if (config.verbose) {
                std::cout << "Found " << files.size() << " PCAP files" << std::endl;
            }

            for (size_t i = 0; i < files.size(); i++) {
                QString output_path = cfgCheck.generate_output_path(config, files[i]);

                if (config.verbose) {
                    std::cout << "[" << (i+1) << "/" << files.size()
                    << "] Analyzing: " << files[i].toStdString() << std::endl;
                }

                report.setPcapFileName(files[i]);
                analyzer.analyzePcapFile(files[i].toStdString(), &report);
            }

            report.saveToFile();
        }

        if (config.verbose) {
            std::cout << "Analysis completed successfully." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 5;
    }

    return 0;

    //return a.exec();
}
