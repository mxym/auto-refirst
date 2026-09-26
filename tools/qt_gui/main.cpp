// Optional Qt Widgets front end for auto-refirst.
//
// This client intentionally owns no parser or detector code.  It is a visual
// queue and evidence browser around the existing CLI process contract, so the
// CLI remains the one source of truth for analysis, limits, and safety policy.

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QCoreApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QGridLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMimeData>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QUrl>
#include <QVector>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace {

constexpr qint64 kUiOutputCap = 64ll * 1024ll * 1024ll;
constexpr qint64 kUiErrorCap = 4ll * 1024ll * 1024ll;

struct QueueItem {
    QString path;
    QString state = QStringLiteral("Queued");
    QString format;
    QString evidence;
    QString report_path;
    QString detail;
    QJsonObject report;
};

QStringList uniqueStrings(const QStringList& values) {
    QStringList out;
    for (const auto& value : values) {
        if (!value.isEmpty() && !out.contains(value)) out.push_back(value);
    }
    return out;
}

QString stateText(const QString& state) {
    return state.isEmpty() ? QStringLiteral("UNSPECIFIED") : state.toUpper();
}

QString shortPath(const QString& path) {
    const QFileInfo info(path);
    const QString name = info.fileName();
    return name.isEmpty() ? QDir::toNativeSeparators(path) : name;
}

class MainWindow final : public QMainWindow {
public:
    MainWindow() {
        setAcceptDrops(true);
        setWindowTitle(QStringLiteral("auto-refirst  ·  Evidence workspace"));
        resize(1220, 780);
        setMinimumSize(980, 640);

        buildUi();
        detectCli();
        const QString documents = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
        m_output_edit->setText(QDir(documents).filePath(QStringLiteral("auto-refirst-reports")));
        const QByteArray output_override = qgetenv("AUTO_REFIRST_GUI_OUTPUT");
        if (!output_override.isEmpty()) m_output_edit->setText(QString::fromLocal8Bit(output_override));
        const QByteArray screenshot_override = qgetenv("AUTO_REFIRST_GUI_SCREENSHOT");
        if (!screenshot_override.isEmpty()) m_screenshot_path = QString::fromLocal8Bit(screenshot_override);
        m_exit_after_analysis = qgetenv("AUTO_REFIRST_GUI_EXIT_AFTER_ANALYSIS") == QByteArrayLiteral("1");
        setStatus(QStringLiteral("拖放文件或目录开始；默认只做静态预处理，不执行样本。"));
    }

    void enqueueStartupPaths(const QStringList& paths) {
        int added = 0;
        for (const auto& path : paths) if (addPath(path)) ++added;
        if (added > 0) {
            setStatus(QStringLiteral("已从启动参数加入 %1 个样本，正在自动分析。").arg(added));
            QTimer::singleShot(0, this, [this] { startPending(); });
        }
    }

protected:
    void closeEvent(QCloseEvent* event) override {
        m_closing = true;
        m_timeout_timer->stop();
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            (void)m_process->waitForFinished(1500);
        }
        event->accept();
    }

    void dragEnterEvent(QDragEnterEvent* event) override {
        if (event->mimeData()->hasUrls()) event->acceptProposedAction();
    }

    void dropEvent(QDropEvent* event) override {
        int added = 0;
        for (const auto& url : event->mimeData()->urls()) {
            if (!url.isLocalFile()) {
                setStatus(QStringLiteral("已忽略非本地拖放项：%1").arg(url.toString()));
                continue;
            }
            if (addPath(url.toLocalFile())) ++added;
        }
        if (added > 0) {
            setStatus(QStringLiteral("已加入 %1 个样本，正在自动分析待处理项。").arg(added));
            startPending();
        }
        event->acceptProposedAction();
    }

private:
    void buildUi() {
        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);
        root->setContentsMargins(22, 18, 22, 16);
        root->setSpacing(12);

        auto* header = new QHBoxLayout();
        auto* heading = new QVBoxLayout();
        auto* title = new QLabel(QStringLiteral("auto-refirst"));
        title->setObjectName(QStringLiteral("title"));
        auto* subtitle = new QLabel(QStringLiteral("Evidence workspace  /  bounded static preparation for unusual binaries"));
        subtitle->setObjectName(QStringLiteral("subtitle"));
        heading->addWidget(title);
        heading->addWidget(subtitle);
        header->addLayout(heading, 1);
        m_add_file = new QPushButton(QStringLiteral("＋ 添加文件"));
        m_add_dir = new QPushButton(QStringLiteral("＋ 添加目录"));
        m_clear = new QPushButton(QStringLiteral("清空队列"));
        m_start = new QPushButton(QStringLiteral("▶ 开始分析"));
        m_start->setObjectName(QStringLiteral("primary"));
        m_cancel = new QPushButton(QStringLiteral("■ 取消"));
        m_cancel->setEnabled(false);
        header->addWidget(m_add_file);
        header->addWidget(m_add_dir);
        header->addWidget(m_clear);
        header->addWidget(m_start);
        header->addWidget(m_cancel);
        root->addLayout(header);

        auto* splitter = new QSplitter(Qt::Horizontal, central);
        splitter->setChildrenCollapsible(false);

        auto* queue_box = new QGroupBox(QStringLiteral("样本队列  ·  拖放文件/目录到这里"));
        auto* queue_layout = new QVBoxLayout(queue_box);
        queue_layout->setContentsMargins(10, 16, 10, 10);
        m_queue_table = new QTableWidget(0, 5, queue_box);
        m_queue_table->setHorizontalHeaderLabels({QStringLiteral("样本"), QStringLiteral("状态"), QStringLiteral("格式"), QStringLiteral("证据"), QStringLiteral("报告")});
        m_queue_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_queue_table->setSelectionMode(QAbstractItemView::SingleSelection);
        m_queue_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_queue_table->setSortingEnabled(false);
        m_queue_table->verticalHeader()->setVisible(false);
        m_queue_table->horizontalHeader()->setStretchLastSection(true);
        m_queue_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        m_queue_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        m_queue_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        m_queue_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        queue_layout->addWidget(m_queue_table, 1);
        auto* hint = new QLabel(QStringLiteral("建议先看 CONFIRMED/LIKELY 证据，再沿报告中的限制与下一步路线人工复核。"));
        hint->setObjectName(QStringLiteral("hint"));
        hint->setWordWrap(true);
        queue_layout->addWidget(hint);
        splitter->addWidget(queue_box);

        auto* detail_box = new QGroupBox(QStringLiteral("证据摘要"));
        auto* detail_layout = new QVBoxLayout(detail_box);
        detail_layout->setContentsMargins(12, 16, 12, 12);
        m_summary = new QLabel(QStringLiteral("选择一行查看摘要"));
        m_summary->setObjectName(QStringLiteral("summary"));
        m_summary->setWordWrap(true);
        detail_layout->addWidget(m_summary);
        m_detail = new QTextEdit();
        m_detail->setReadOnly(true);
        m_detail->setLineWrapMode(QTextEdit::WidgetWidth);
        m_detail->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        detail_layout->addWidget(m_detail, 1);
        auto* open_row = new QHBoxLayout();
        m_open_report = new QPushButton(QStringLiteral("打开报告"));
        m_open_output = new QPushButton(QStringLiteral("打开输出目录"));
        m_open_report->setEnabled(false);
        m_open_output->setEnabled(false);
        open_row->addWidget(m_open_report);
        open_row->addWidget(m_open_output);
        open_row->addStretch(1);
        detail_layout->addLayout(open_row);
        splitter->addWidget(detail_box);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        root->addWidget(splitter, 1);

        auto* settings = new QGroupBox(QStringLiteral("分析设置"));
        auto* settings_layout = new QGridLayout(settings);
        settings_layout->setContentsMargins(12, 14, 12, 10);
        settings_layout->addWidget(new QLabel(QStringLiteral("CLI")), 0, 0);
        m_cli_edit = new QLineEdit();
        m_cli_edit->setToolTip(QStringLiteral("与 GUI 同目录的 auto-refirst，或 PATH 中的可执行文件"));
        settings_layout->addWidget(m_cli_edit, 0, 1, 1, 4);
        auto* choose_cli = new QPushButton(QStringLiteral("选择…"));
        settings_layout->addWidget(choose_cli, 0, 5);
        settings_layout->addWidget(new QLabel(QStringLiteral("报告目录")), 1, 0);
        m_output_edit = new QLineEdit();
        settings_layout->addWidget(m_output_edit, 1, 1, 1, 4);
        auto* choose_output = new QPushButton(QStringLiteral("选择…"));
        settings_layout->addWidget(choose_output, 1, 5);
        m_extract = new QCheckBox(QStringLiteral("展开静态容器 (--extract)"));
        m_extract->setToolTip(QStringLiteral("仅增加有界静态工件展开；GUI 不提供 --run/--apply 入口。"));
        settings_layout->addWidget(m_extract, 2, 1, 1, 2);
        settings_layout->addWidget(new QLabel(QStringLiteral("单项超时")), 2, 3);
        m_timeout = new QSpinBox();
        m_timeout->setRange(1, 3600);
        m_timeout->setValue(120);
        m_timeout->setSuffix(QStringLiteral(" 秒"));
        settings_layout->addWidget(m_timeout, 2, 4);
        auto* safety = new QLabel(QStringLiteral("静态模式 · 运行时授权与写回功能需在 CLI 隔离环境中显式操作"));
        safety->setObjectName(QStringLiteral("safety"));
        settings_layout->addWidget(safety, 2, 5);
        root->addWidget(settings);

        auto* footer = new QHBoxLayout();
        m_progress = new QProgressBar();
        m_progress->setRange(0, 0);
        m_progress->setValue(0);
        m_progress->setTextVisible(true);
        m_progress->setFormat(QStringLiteral("等待样本"));
        footer->addWidget(m_progress, 1);
        m_status = new QLabel();
        m_status->setObjectName(QStringLiteral("status"));
        m_status->setMinimumWidth(300);
        m_status->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        footer->addWidget(m_status);
        root->addLayout(footer);

        setCentralWidget(central);
        setStyleSheet(QStringLiteral(
            "QMainWindow { background:#0b1220; color:#e5e7eb; }"
            "QGroupBox { border:1px solid #25324a; border-radius:10px; margin-top:8px; padding-top:10px; color:#a9b8d0; font-weight:600; }"
            "QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 6px; background:#0b1220; }"
            "QLabel#title { color:#f8fafc; font-size:27px; font-weight:700; }"
            "QLabel#subtitle, QLabel#hint { color:#8091ad; }"
            "QLabel#summary { color:#dbeafe; padding:4px; font-size:14px; }"
            "QLabel#safety { color:#f0b35b; font-size:11px; }"
            "QLabel#status { color:#8fa4c2; }"
            "QPushButton { background:#18243a; color:#dbeafe; border:1px solid #324666; border-radius:6px; padding:7px 12px; }"
            "QPushButton:hover { background:#223452; border-color:#5b8bd9; }"
            "QPushButton:disabled { color:#60708a; background:#111a2a; border-color:#223049; }"
            "QPushButton#primary { background:#2563eb; border-color:#3b82f6; color:white; font-weight:700; }"
            "QPushButton#primary:hover { background:#3475f0; }"
            "QLineEdit, QSpinBox { background:#111b2d; color:#e5e7eb; border:1px solid #30435f; border-radius:5px; padding:6px; }"
            "QTableWidget, QTextEdit { background:#0f192b; color:#dce8f7; border:1px solid #253b5a; border-radius:6px; gridline-color:#1f304a; }"
            "QHeaderView::section { background:#17243a; color:#9db0cc; border:0; padding:6px; }"
            "QTableWidget::item:selected { background:#1e497b; color:white; }"
            "QProgressBar { background:#111b2d; border:1px solid #293d5a; border-radius:5px; color:#cfe2ff; text-align:center; height:18px; }"
            "QProgressBar::chunk { background:#2563eb; border-radius:4px; }"));

        m_process = new QProcess(this);
        m_timeout_timer = new QTimer(this);
        m_timeout_timer->setSingleShot(true);

        connect(m_add_file, &QPushButton::clicked, this, [this] { addFiles(); });
        connect(m_add_dir, &QPushButton::clicked, this, [this] { addDirectory(); });
        connect(m_clear, &QPushButton::clicked, this, [this] { clearQueue(); });
        connect(m_start, &QPushButton::clicked, this, [this] { startAnalysis(); });
        connect(m_cancel, &QPushButton::clicked, this, [this] { cancelAnalysis(); });
        connect(choose_cli, &QPushButton::clicked, this, [this] { chooseCli(); });
        connect(choose_output, &QPushButton::clicked, this, [this] { chooseOutput(); });
        connect(m_open_report, &QPushButton::clicked, this, [this] { openReport(); });
        connect(m_open_output, &QPushButton::clicked, this, [this] { openOutput(); });
        connect(m_queue_table, &QTableWidget::itemSelectionChanged, this, [this] { showSelected(); });
        connect(m_queue_table, &QTableWidget::cellDoubleClicked, this, [this](int, int) { openReport(); });
        connect(m_process, &QProcess::readyReadStandardOutput, this, [this] { consumeOutput(); });
        connect(m_process, &QProcess::readyReadStandardError, this, [this] { consumeError(); });
        connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
            if (m_start_error.isEmpty()) m_start_error = m_process->errorString();
            // FailedToStart can emit only errorOccurred on some Qt versions;
            // schedule a single fallback so one bad CLI path cannot stall the
            // rest of the queue.  A later finished signal is harmless because
            // the row is cleared before it can be processed twice.
            if (m_current >= 0 && m_process->state() == QProcess::NotRunning)
                QTimer::singleShot(0, this, [this] { if (m_current >= 0 && m_process->state() == QProcess::NotRunning) finishWithoutProcess(); });
        });
        connect(m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int code, QProcess::ExitStatus status) { processFinished(code, status); });
        connect(m_timeout_timer, &QTimer::timeout, this, [this] { processTimedOut(); });
    }

    void detectCli() {
        const QByteArray override_path = qgetenv("AUTO_REFIRST_CLI");
        if (!override_path.isEmpty()) {
            m_cli_edit->setText(QString::fromLocal8Bit(override_path));
            return;
        }
        const QString exe = QCoreApplication::applicationDirPath() + QDir::separator() +
#ifdef Q_OS_WIN
            QStringLiteral("auto-refirst.exe");
#else
            QStringLiteral("auto-refirst");
#endif
        if (QFileInfo(exe).isFile()) {
            m_cli_edit->setText(QDir::toNativeSeparators(exe));
            return;
        }
        const QString fromPath = QStandardPaths::findExecutable(QStringLiteral("auto-refirst"));
        m_cli_edit->setText(fromPath.isEmpty() ? QStringLiteral("auto-refirst") : fromPath);
    }

    bool addPath(const QString& path) {
        const QFileInfo info(path);
        if (!info.exists() || (!info.isFile() && !info.isDir())) {
            setStatus(QStringLiteral("无法加入：不是常规文件或目录：%1").arg(path));
            return false;
        }
        const QString absolute = info.absoluteFilePath();
        for (const auto& item : m_items) {
            if (QFileInfo(item.path).absoluteFilePath() == absolute) return false;
        }
        QueueItem item;
        item.path = absolute;
        m_items.push_back(item);
        const int row = m_queue_table->rowCount();
        m_queue_table->insertRow(row);
        m_queue_table->setItem(row, 0, new QTableWidgetItem(shortPath(absolute)));
        m_queue_table->item(row, 0)->setToolTip(QDir::toNativeSeparators(absolute));
        m_queue_table->setItem(row, 1, new QTableWidgetItem(item.state));
        m_queue_table->setItem(row, 2, new QTableWidgetItem(QStringLiteral("待识别")));
        m_queue_table->setItem(row, 3, new QTableWidgetItem(QStringLiteral("—")));
        m_queue_table->setItem(row, 4, new QTableWidgetItem(QStringLiteral("—")));
        return true;
    }

    void addFiles() {
        const auto files = QFileDialog::getOpenFileNames(this, QStringLiteral("选择样本文件"));
        int added = 0;
        for (const auto& file : files) if (addPath(file)) ++added;
        if (added) {
            setStatus(QStringLiteral("已加入 %1 个样本，正在自动分析待处理项。").arg(added));
            startPending();
        }
    }

    void addDirectory() {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("选择样本目录"));
        if (!dir.isEmpty() && addPath(dir)) {
            setStatus(QStringLiteral("已加入目录：%1，正在自动分析。").arg(shortPath(dir)));
            startPending();
        }
    }

    void clearQueue() {
        if (m_current >= 0) {
            setStatus(QStringLiteral("分析进行中，先取消当前任务再清空队列。"));
            return;
        }
        m_items.clear();
        m_queue_table->setRowCount(0);
        m_detail->clear();
        m_summary->setText(QStringLiteral("选择一行查看摘要"));
        m_open_report->setEnabled(false);
        m_open_output->setEnabled(false);
        m_progress->setRange(0, 0);
        m_progress->setFormat(QStringLiteral("等待样本"));
        setStatus(QStringLiteral("队列已清空。"));
    }

    void chooseCli() {
        const QString selected = QFileDialog::getOpenFileName(this, QStringLiteral("选择 auto-refirst 可执行文件"), m_cli_edit->text());
        if (!selected.isEmpty()) m_cli_edit->setText(selected);
    }

    void chooseOutput() {
        const QString selected = QFileDialog::getExistingDirectory(this, QStringLiteral("选择报告输出目录"), m_output_edit->text());
        if (!selected.isEmpty()) m_output_edit->setText(selected);
    }

    void startAnalysis() {
        if (m_current >= 0) return;
        if (m_items.isEmpty()) {
            setStatus(QStringLiteral("队列为空：拖放一个文件或目录，或点击添加按钮。"));
            return;
        }
        m_cancel_requested = false;
        m_next = 0;
        m_completed = 0;
        for (int i = 0; i < m_queue_table->rowCount(); ++i) {
            setCell(i, 1, QStringLiteral("Queued"));
            setCell(i, 2, QStringLiteral("待识别"));
            setCell(i, 3, QStringLiteral("—"));
            setCell(i, 4, QStringLiteral("—"));
            m_items[i].state = QStringLiteral("Queued");
            m_items[i].format.clear();
            m_items[i].evidence.clear();
            m_items[i].report_path.clear();
            m_items[i].report = {};
        }
        m_progress->setRange(0, m_items.size());
        m_progress->setValue(0);
        m_progress->setFormat(QStringLiteral("%v / %m"));
        m_start->setEnabled(false);
        m_cancel->setEnabled(true);
        startNext();
    }

    void startPending() {
        if (m_current >= 0) return;
        bool pending = false;
        for (const auto& item : m_items) {
            if (item.state == QStringLiteral("Queued")) {
                pending = true;
                break;
            }
        }
        if (!pending) return;
        m_cancel_requested = false;
        m_next = 0;
        m_progress->setRange(0, m_items.size());
        m_completed = terminalCount();
        m_progress->setValue(m_completed);
        m_progress->setFormat(QStringLiteral("%v / %m"));
        m_start->setEnabled(false);
        m_cancel->setEnabled(true);
        startNext();
    }

    void startNext() {
        while (m_next < m_items.size() && m_items[m_next].state != QStringLiteral("Queued")) ++m_next;
        if (m_cancel_requested || m_next >= m_items.size()) {
            m_current = -1;
            m_start->setEnabled(true);
            m_cancel->setEnabled(false);
            m_progress->setValue(terminalCount());
            if (m_cancel_requested) setStatus(QStringLiteral("分析已取消；已完成的报告仍可打开。"));
            else setStatus(QStringLiteral("队列分析完成。"));
            return;
        }
        m_current = m_next++;
        m_stdout.clear();
        m_stderr.clear();
        m_start_error.clear();
        m_timed_out = false;
        m_items[m_current].state = QStringLiteral("Running");
        setCell(m_current, 1, QStringLiteral("分析中…"));
        const QString program = m_cli_edit->text().trimmed();
        if (program.isEmpty()) {
            m_start_error = QStringLiteral("未设置 auto-refirst 可执行文件");
            finishWithoutProcess();
            return;
        }
        QStringList args;
        args << m_items[m_current].path << QStringLiteral("--json") << QStringLiteral("--json-envelope") << QStringLiteral("--json-errors");
        if (m_extract->isChecked()) args << QStringLiteral("--extract");
        m_process->setProgram(program);
        m_process->setArguments(args);
        const QFileInfo program_info(program);
        if (program_info.isAbsolute() && program_info.isFile())
            m_process->setWorkingDirectory(program_info.absolutePath());
        m_process->start();
        if (!m_process->waitForStarted(2000)) {
            m_start_error = m_process->errorString().isEmpty()
                ? QStringLiteral("无法启动 CLI") : m_process->errorString();
            finishWithoutProcess();
            return;
        }
        m_timeout_timer->start(m_timeout->value() * 1000);
        m_progress->setFormat(QStringLiteral("%v / %m  ·  %1").arg(shortPath(m_items[m_current].path)));
        setStatus(QStringLiteral("正在分析 %1…").arg(shortPath(m_items[m_current].path)));
    }

    void consumeOutput() {
        if (m_current < 0) return;
        m_stdout += m_process->readAllStandardOutput();
        if (m_stdout.size() > kUiOutputCap) {
            m_start_error = QStringLiteral("报告超过 GUI 的 64 MiB 展示上限；请直接使用 CLI 保存完整输出");
            m_process->kill();
        }
    }

    void consumeError() {
        if (m_current >= 0) m_stderr += m_process->readAllStandardError();
        if (m_stderr.size() > kUiErrorCap) {
            m_stderr.truncate(static_cast<int>(kUiErrorCap));
            if (m_start_error.isEmpty()) m_start_error = QStringLiteral("CLI stderr 超过 GUI 的 4 MiB 错误输出上限");
            if (m_process->state() != QProcess::NotRunning) m_process->kill();
        }
    }

    void processTimedOut() {
        if (m_current < 0 || m_process->state() == QProcess::NotRunning) return;
        m_timed_out = true;
        m_start_error = QStringLiteral("单项分析超过 %1 秒，已终止进程").arg(m_timeout->value());
        m_process->kill();
    }

    void cancelAnalysis() {
        if (m_current < 0) return;
        m_cancel_requested = true;
        for (int i = 0; i < m_items.size(); ++i) {
            if (m_items[i].state == QStringLiteral("Queued")) {
                m_items[i].state = QStringLiteral("Cancelled");
                setCell(i, 1, QStringLiteral("已取消"));
            }
        }
        if (m_process->state() != QProcess::NotRunning) {
            m_items[m_current].state = QStringLiteral("Cancelled");
            m_process->kill();
        } else {
            finishWithoutProcess();
        }
    }

    void processFinished(int exit_code, QProcess::ExitStatus exit_status) {
        if (m_current < 0) return;
        m_timeout_timer->stop();
        consumeOutput();
        consumeError();
        const int row = m_current;
        if (m_closing) {
            m_current = -1;
            return;
        }
        if (m_cancel_requested || m_items[row].state == QStringLiteral("Cancelled")) {
            m_items[row].state = QStringLiteral("Cancelled");
            setCell(row, 1, QStringLiteral("已取消"));
        } else if (m_timed_out || !m_start_error.isEmpty()) {
            finishFailure(row, m_timed_out ? m_start_error : m_start_error);
        } else if (exit_status != QProcess::NormalExit || exit_code != 0) {
            QString message = parseErrorMessage(m_stderr);
            if (message.isEmpty()) message = QString::fromUtf8(m_stderr).trimmed();
            if (message.isEmpty()) message = QStringLiteral("CLI 退出码 %1").arg(exit_code);
            finishFailure(row, message);
        } else {
            QJsonParseError parse_error{};
            const QJsonDocument document = QJsonDocument::fromJson(m_stdout, &parse_error);
            if (!document.isObject()) {
                finishFailure(row, QStringLiteral("CLI 输出不是 JSON object：%1").arg(parse_error.errorString()));
            } else {
                const QJsonObject object = document.object();
                QString report_error;
                const QString report_path = writeReport(m_items[row], m_stdout, report_error);
                if (report_path.isEmpty()) {
                    finishFailure(row, report_error);
                } else {
                    m_items[row].report = object;
                    m_items[row].report_path = report_path;
                    m_items[row].state = QStringLiteral("Done");
                    renderSummary(object, m_items[row].format, m_items[row].evidence, m_items[row].detail);
                    setCell(row, 1, m_items[row].evidence.contains(QStringLiteral("partial"), Qt::CaseInsensitive) ? QStringLiteral("完成 · partial") : QStringLiteral("完成"));
                    setCell(row, 2, m_items[row].format);
                    setCell(row, 3, m_items[row].evidence);
                    setCell(row, 4, QFileInfo(report_path).fileName());
                    setStatus(QStringLiteral("已完成：%1").arg(shortPath(m_items[row].path)));
                    showSelectedIf(row);
                }
            }
        }
        ++m_completed;
        m_progress->setValue(terminalCount());
        m_current = -1;
        maybeFinishAutomation();
        QTimer::singleShot(0, this, [this] { startNext(); });
    }

    void finishWithoutProcess() {
        if (m_current < 0) return;
        const int row = m_current;
        m_timeout_timer->stop();
        if (m_cancel_requested || m_items[row].state == QStringLiteral("Cancelled")) {
            m_items[row].state = QStringLiteral("Cancelled");
            setCell(row, 1, QStringLiteral("已取消"));
        } else {
            finishFailure(row, m_start_error.isEmpty() ? QStringLiteral("无法启动 CLI") : m_start_error);
        }
        ++m_completed;
        m_progress->setValue(terminalCount());
        m_current = -1;
        maybeFinishAutomation();
        QTimer::singleShot(0, this, [this] { startNext(); });
    }

    void finishFailure(int row, const QString& message) {
        m_items[row].state = QStringLiteral("Failed");
        m_items[row].detail = QStringLiteral("[FAILED] %1\n\n%2").arg(message, QString::fromUtf8(m_stderr).trimmed());
        setCell(row, 1, QStringLiteral("失败"));
        setCell(row, 2, QStringLiteral("—"));
        setCell(row, 3, QStringLiteral("查看详情"));
        setCell(row, 4, QStringLiteral("—"));
        showSelectedIf(row);
        setStatus(QStringLiteral("分析失败：%1").arg(message));
    }

    QString writeReport(const QueueItem& item, const QByteArray& output, QString& error) const {
        QString directory = m_output_edit->text().trimmed();
        if (directory.isEmpty()) {
            error = QStringLiteral("报告目录为空");
            return {};
        }
        QDir out(directory);
        if (!out.mkpath(QStringLiteral("."))) {
            error = QStringLiteral("无法创建报告目录：%1").arg(directory);
            return {};
        }
        QString base = QFileInfo(item.path).completeBaseName();
        if (base.isEmpty()) base = QStringLiteral("sample");
        base.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9._-]+")), QStringLiteral("_"));
        const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-hhmmss-zzz"));
        QString candidate = out.filePath(base + QStringLiteral("-") + stamp + QStringLiteral(".json"));
        int suffix = 2;
        while (QFileInfo::exists(candidate)) candidate = out.filePath(base + QStringLiteral("-") + stamp + QStringLiteral("-") + QString::number(suffix++) + QStringLiteral(".json"));
        QFile file(candidate);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            error = QStringLiteral("无法写入报告：%1").arg(file.errorString());
            return {};
        }
        if (file.write(output) != output.size()) {
            error = QStringLiteral("报告写入不完整：%1").arg(file.errorString());
            return {};
        }
        file.close();
        return QFileInfo(candidate).absoluteFilePath();
    }

    QString parseErrorMessage(const QByteArray& bytes) const {
        QJsonParseError error{};
        const QJsonDocument document = QJsonDocument::fromJson(bytes, &error);
        if (!document.isObject()) return {};
        const QJsonObject root = document.object().value(QStringLiteral("error")).toObject();
        if (root.isEmpty()) return {};
        const QString stage = root.value(QStringLiteral("stage")).toString();
        const QString message = root.value(QStringLiteral("message")).toString();
        return stage.isEmpty() ? message : stage + QStringLiteral(": ") + message;
    }

    void renderSummary(const QJsonObject& root, QString& format, QString& evidence, QString& detail) const {
        QJsonArray reports;
        if (root.value(QStringLiteral("reports")).isArray()) reports = root.value(QStringLiteral("reports")).toArray();
        else reports.push_back(root);

        QStringList formats;
        QStringList lines;
        QStringList limitations;
        int findings = 0;
        int confirmed = 0;
        int review = 0;
        bool partial = false;
        QString hypothesis;
        for (const auto& value : reports) {
            const QJsonObject report = value.toObject();
            const QJsonObject report_format = report.value(QStringLiteral("format")).toObject();
            const QString kind = report_format.value(QStringLiteral("kind")).toString();
            if (!kind.isEmpty()) formats.push_back(kind);
            const QJsonArray finding_array = report.value(QStringLiteral("findings")).toArray();
            for (const auto& finding_value : finding_array) {
                const QJsonObject finding = finding_value.toObject();
                ++findings;
                const QString state = stateText(finding.value(QStringLiteral("state")).toString());
                if (state == QStringLiteral("CONFIRMED")) ++confirmed;
                else ++review;
                if (lines.size() < 18) {
                    const QString family = finding.value(QStringLiteral("family")).toString();
                    const QString variant = finding.value(QStringLiteral("variant")).toString();
                    const QJsonArray ev = finding.value(QStringLiteral("evidence")).toArray();
                    QString evidence_text = ev.isEmpty() ? QString() : ev.first().toString();
                    QString label = family.isEmpty() ? finding.value(QStringLiteral("kind")).toString() : family;
                    if (!variant.isEmpty()) label += QStringLiteral(" / ") + variant;
                    lines.push_back(QStringLiteral("[%1] %2%3").arg(state, label, evidence_text.isEmpty() ? QString() : QStringLiteral("  — ") + evidence_text));
                }
            }
            const QJsonObject materialization = report.value(QStringLiteral("materialization")).toObject();
            if (materialization.value(QStringLiteral("partial")).toBool()) partial = true;
            for (const auto& reason : materialization.value(QStringLiteral("reasons")).toArray()) if (limitations.size() < 12) limitations.push_back(reason.toString());
            const QJsonObject graph = report.value(QStringLiteral("artifact_graph")).toObject();
            if (graph.value(QStringLiteral("truncated")).toBool()) partial = true;
            for (const auto& warning : graph.value(QStringLiteral("warnings")).toArray()) if (limitations.size() < 12) limitations.push_back(warning.toString());
            if (hypothesis.isEmpty()) hypothesis = report.value(QStringLiteral("analysis_guidance")).toObject().value(QStringLiteral("visible_hypothesis")).toString();
        }
        const QJsonObject directory = root.value(QStringLiteral("directory_summary")).toObject();
        if (!directory.isEmpty()) {
            partial = partial || directory.value(QStringLiteral("partial")).toBool();
            const auto ecosystems = directory.value(QStringLiteral("confirmed_ecosystems")).toArray();
            for (const auto& ecosystem : ecosystems) formats.push_back(ecosystem.toString());
            for (const auto& reason : directory.value(QStringLiteral("partial_reasons")).toArray()) if (limitations.size() < 12) limitations.push_back(reason.toString());
            format = QStringLiteral("目录 · %1 文件").arg(directory.value(QStringLiteral("analyzed_files")).toInt());
        } else {
            const auto compact = uniqueStrings(formats);
            format = compact.isEmpty() ? QStringLiteral("unknown") : compact.join(QStringLiteral(", "));
        }
        const QJsonObject rendering = root.value(QStringLiteral("report_rendering")).toObject();
        if (rendering.value(QStringLiteral("partial")).toBool()) partial = true;
        if (rendering.value(QStringLiteral("reason")).isString() && rendering.value(QStringLiteral("partial")).toBool() && limitations.size() < 12) limitations.push_back(rendering.value(QStringLiteral("reason")).toString());
        const QJsonObject artifacts = root.value(QStringLiteral("artifact_materialization")).toObject();
        if (artifacts.value(QStringLiteral("partial")).toBool()) partial = true;

        evidence = QStringLiteral("%1 findings  ·  %2 confirmed  ·  %3 review").arg(findings).arg(confirmed).arg(review);
        if (partial) evidence += QStringLiteral("  ·  partial");
        detail = QStringLiteral("INPUT\n%1\n\nFORMAT\n%2\n\nEVIDENCE\n%3\n\n").arg(root.value(QStringLiteral("input")).toString(), format, evidence);
        if (!directory.isEmpty()) detail.replace(QStringLiteral("INPUT\n\n"), QStringLiteral("INPUT\n%1\n\n").arg(directory.value(QStringLiteral("root")).toString()));
        if (!hypothesis.isEmpty()) detail += QStringLiteral("VISIBLE HYPOTHESIS\n%1\n\n").arg(hypothesis);
        detail += QStringLiteral("KEY FINDINGS\n");
        if (lines.isEmpty()) detail += QStringLiteral("(no rendered findings)\n");
        else detail += lines.join(QStringLiteral("\n")) + QLatin1Char('\n');
        detail += QStringLiteral("\nLIMITATIONS / LOW CONFIDENCE\n");
        detail += QStringLiteral("Default UI mode is static. LIKELY, SUSPECTED, ROUTE_HINT, partial, and budget-limited states need manual review; no signature trust or runtime execution is inferred.\n");
        for (const auto& limitation : uniqueStrings(limitations)) detail += QStringLiteral("• ") + limitation + QLatin1Char('\n');
    }

    void showSelected() {
        const int row = m_queue_table->currentRow();
        showItemDetails(row);
    }

    void showSelectedIf(int row) {
        if (m_queue_table->currentRow() == row || m_queue_table->currentRow() < 0) {
            m_queue_table->selectRow(row);
            showItemDetails(row);
        }
    }

    void showItemDetails(int row) {
        if (row < 0 || row >= m_items.size()) return;
        const auto& item = m_items[row];
        if (item.report.isEmpty()) {
            m_summary->setText(QStringLiteral("%1  ·  %2").arg(shortPath(item.path), item.state));
            m_detail->setPlainText(item.detail.isEmpty() ? QStringLiteral("等待分析结果…") : item.detail);
        } else {
            m_summary->setText(QStringLiteral("%1  ·  %2  ·  %3").arg(shortPath(item.path), item.format, item.evidence));
            m_detail->setPlainText(item.detail);
        }
        m_open_report->setEnabled(!item.report_path.isEmpty() && QFileInfo::exists(item.report_path));
        m_open_output->setEnabled(!item.report_path.isEmpty() || !m_output_edit->text().trimmed().isEmpty());
    }

    void openReport() {
        const int row = m_queue_table->currentRow();
        if (row < 0 || row >= m_items.size() || m_items[row].report_path.isEmpty()) return;
        QDesktopServices::openUrl(QUrl::fromLocalFile(m_items[row].report_path));
    }

    void openOutput() {
        const int row = m_queue_table->currentRow();
        QString path = (row >= 0 && row < m_items.size() && !m_items[row].report_path.isEmpty())
            ? QFileInfo(m_items[row].report_path).absolutePath() : m_output_edit->text().trimmed();
        if (!path.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    }

    void setCell(int row, int column, const QString& value) {
        if (row < 0 || row >= m_queue_table->rowCount()) return;
        if (!m_queue_table->item(row, column)) m_queue_table->setItem(row, column, new QTableWidgetItem());
        m_queue_table->item(row, column)->setText(value);
    }

    void setStatus(const QString& status) { m_status->setText(status); }

    int terminalCount() const {
        int count = 0;
        for (const auto& item : m_items) {
            if (item.state == QStringLiteral("Done") || item.state == QStringLiteral("Failed") || item.state == QStringLiteral("Cancelled")) ++count;
        }
        return count;
    }

    void maybeFinishAutomation() {
        if (m_automation_scheduled || m_screenshot_path.isEmpty() || m_items.isEmpty() || terminalCount() != m_items.size()) return;
        m_automation_scheduled = true;
        QTimer::singleShot(250, this, [this] {
            grab().save(m_screenshot_path);
            if (m_exit_after_analysis) QCoreApplication::quit();
        });
    }

    QTableWidget* m_queue_table = nullptr;
    QTextEdit* m_detail = nullptr;
    QLabel* m_summary = nullptr;
    QLabel* m_status = nullptr;
    QProgressBar* m_progress = nullptr;
    QLineEdit* m_cli_edit = nullptr;
    QLineEdit* m_output_edit = nullptr;
    QSpinBox* m_timeout = nullptr;
    QCheckBox* m_extract = nullptr;
    QPushButton* m_add_file = nullptr;
    QPushButton* m_add_dir = nullptr;
    QPushButton* m_clear = nullptr;
    QPushButton* m_start = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_open_report = nullptr;
    QPushButton* m_open_output = nullptr;
    QProcess* m_process = nullptr;
    QTimer* m_timeout_timer = nullptr;
    QVector<QueueItem> m_items;
    QByteArray m_stdout;
    QByteArray m_stderr;
    QString m_start_error;
    int m_current = -1;
    int m_next = 0;
    bool m_cancel_requested = false;
    bool m_timed_out = false;
    bool m_closing = false;
    int m_completed = 0;
    QString m_screenshot_path;
    bool m_exit_after_analysis = false;
    bool m_automation_scheduled = false;
};

} // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("auto-refirst-gui"));
    app.setOrganizationName(QStringLiteral("mxym"));
    MainWindow window;
    QStringList startup_paths;
    for (int i = 1; i < argc; ++i) {
        const QString path = QString::fromLocal8Bit(argv[i]);
        if (!path.startsWith(QLatin1Char('-'))) startup_paths.push_back(path);
    }
    if (!startup_paths.isEmpty()) window.enqueueStartupPaths(startup_paths);
    window.show();
    return app.exec();
}
