#ifndef COMMCONFIG_H
#define COMMCONFIG_H

#include <qobject.h>

struct Config {
    // 模式
    enum Mode { MODE_NONE, MODE_FILE, MODE_DIR } mode = MODE_NONE;

    // 输入
    QString input_path;

    // 输出
    QString output_path;
    QString format = "text";
    bool stats_only = false;
    int limit = 0;

    // 批量模式选项
    bool recursive = false;
    QList<QString> extensions = {".pcap", ".pcapng"};

    // 其他选项
    double threshold = 0.1;
    bool verbose = false;
    bool quiet = false;
};



class CommConfig
{
public:
    CommConfig();

    void print_help();

    void print_version();

    int parse_arguments(int argc, char* argv[], Config& cfg);

    int validate_input(const Config& cfg);

    QList<QString> scan_pcap_files(const QString &dirPath, bool recursive=false);

    QString generate_output_path(const Config& config, const QString& input_file);

};

#endif // COMMCONFIG_H
