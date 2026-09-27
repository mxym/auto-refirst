// Optional Qt Widgets front end for auto-refirst.
//
// This client intentionally owns no parser or detector code.  It is a visual
// queue and evidence browser around the existing CLI process contract, so the
// CLI remains the one source of truth for analysis, limits, and safety policy.

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
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
#include <QHash>
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
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QMessageBox>
#include <QTimer>
#include <QUrl>
#include <QVector>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

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
        const QByteArray search_override = qgetenv("AUTO_REFIRST_GUI_SEARCH");
        if (!search_override.isEmpty()) m_search_edit->setText(QString::fromLocal8Bit(search_override));
        if (qgetenv("AUTO_REFIRST_GUI_LANGUAGE").toLower() == QByteArrayLiteral("en")) m_language->setCurrentIndex(1);
        m_exit_after_analysis = qgetenv("AUTO_REFIRST_GUI_EXIT_AFTER_ANALYSIS") == QByteArrayLiteral("1");
        m_english = m_language->currentIndex() == 1;
        applyLanguage();
        setStatus(m_english ? QStringLiteral("Drop files or folders to start; static preparation is the default.") : QStringLiteral("拖放文件或目录开始；默认只做静态预处理。"));
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
        m_title = title;
        title->setObjectName(QStringLiteral("title"));
        auto* subtitle = new QLabel(QStringLiteral("Evidence workspace  /  bounded static preparation for unusual binaries"));
        m_subtitle = subtitle;
        subtitle->setObjectName(QStringLiteral("subtitle"));
        heading->addWidget(title);
        heading->addWidget(subtitle);
        header->addLayout(heading, 1);
        m_language = new QComboBox();
        m_language->addItem(QStringLiteral("中文"));
        m_language->addItem(QStringLiteral("English"));
        m_language->setToolTip(QStringLiteral("语言 / Language"));
        header->addWidget(m_language);
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
        m_queue_box = queue_box;
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
        auto* hint = new QLabel(QStringLiteral("拖放后会自动开始。双击已完成项打开 JSON 报告。"));
        m_queue_hint = hint;
        hint->setObjectName(QStringLiteral("hint"));
        hint->setWordWrap(true);
        queue_layout->addWidget(hint);
        splitter->addWidget(queue_box);

        auto* detail_box = new QGroupBox(QStringLiteral("报告"));
        m_detail_box = detail_box;
        auto* detail_layout = new QVBoxLayout(detail_box);
        detail_layout->setContentsMargins(12, 16, 12, 12);
        m_summary = new QLabel(QStringLiteral("选择一行查看摘要"));
        m_summary->setObjectName(QStringLiteral("summary"));
        m_summary->setWordWrap(true);
        detail_layout->addWidget(m_summary);
        m_filter_edit = new QLineEdit();
        m_filter_edit->setPlaceholderText(QStringLiteral("筛选发现 / Filter findings"));
        detail_layout->addWidget(m_filter_edit);
        m_detail = new QTextEdit();
        m_detail->setReadOnly(true);
        m_detail->setLineWrapMode(QTextEdit::WidgetWidth);
        m_detail->setFont(QFontDatabase::systemFont(QFontDatabase::GeneralFont));
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
        m_settings = settings;
        auto* settings_layout = new QVBoxLayout(settings);
        settings_layout->setContentsMargins(10, 12, 10, 8);
        m_settings_tabs = new QTabWidget(settings);
        auto* basic_page = new QWidget(m_settings_tabs);
        auto* basic_layout = new QGridLayout(basic_page);
        basic_layout->setContentsMargins(8, 8, 8, 8);
        basic_layout->setHorizontalSpacing(12);
        basic_layout->setVerticalSpacing(7);
        m_output_label = new QLabel(QStringLiteral("报告目录"));
        basic_layout->addWidget(m_output_label, 0, 0);
        m_output_edit = new QLineEdit();
        basic_layout->addWidget(m_output_edit, 0, 1, 1, 5);
        m_choose_output = new QPushButton(QStringLiteral("选择…"));
        basic_layout->addWidget(m_choose_output, 0, 6);
        m_extract = new QCheckBox(QStringLiteral("展开静态容器"));
        m_extract->setToolTip(QStringLiteral("增加有界静态工件展开和重型静态分析。"));
        basic_layout->addWidget(m_extract, 1, 0, 1, 2);
        m_recursive = new QCheckBox(QStringLiteral("递归工件报告"));
        m_recursive->setToolTip(QStringLiteral("与展开一起输出递归工件报告；递归子工件保持静态。"));
        basic_layout->addWidget(m_recursive, 1, 2, 1, 2);
        m_run = new QCheckBox(QStringLiteral("运行时分析"));
        m_run->setToolTip(QStringLiteral("默认关闭；启用前需要确认。"));
        basic_layout->addWidget(m_run, 2, 0);
        m_runtime_mode_label = new QLabel(QStringLiteral("运行模式"));
        basic_layout->addWidget(m_runtime_mode_label, 2, 1);
        m_runtime_mode = new QComboBox();
        m_runtime_mode->addItem(QStringLiteral("自动深度分析"), QString());
        m_runtime_mode->addItem(QStringLiteral("Trace 兼容模式"), QStringLiteral("trace"));
        m_runtime_mode->addItem(QStringLiteral("Unpack 兼容模式"), QStringLiteral("unpack"));
        m_runtime_mode->addItem(QStringLiteral("Python 探针兼容模式"), QStringLiteral("python-probe"));
        m_runtime_mode->setEnabled(false);
        basic_layout->addWidget(m_runtime_mode, 2, 2, 1, 2);
        m_apply = new QCheckBox(QStringLiteral("允许写回"));
        m_apply->setEnabled(false);
        basic_layout->addWidget(m_apply, 2, 4);
        m_timeout_label = new QLabel(QStringLiteral("单项超时"));
        basic_layout->addWidget(m_timeout_label, 2, 5);
        m_timeout = new QSpinBox();
        m_timeout->setRange(1, 3600);
        m_timeout->setValue(120);
        m_timeout->setSuffix(QStringLiteral(" 秒"));
        basic_layout->addWidget(m_timeout, 2, 6);
        m_safety = new QLabel(QStringLiteral("默认只做静态分析；运行时和写回均需主动开启"));
        m_safety->setObjectName(QStringLiteral("safety"));
        basic_layout->addWidget(m_safety, 3, 0, 1, 7);
        basic_layout->setColumnStretch(1, 1);
        basic_layout->setColumnStretch(3, 1);
        basic_layout->setColumnStretch(6, 0);
        m_settings_tabs->addTab(basic_page, QStringLiteral("基础"));

        auto* advanced_page = new QWidget(m_settings_tabs);
        auto* advanced_layout = new QGridLayout(advanced_page);
        advanced_layout->setContentsMargins(8, 8, 8, 8);
        advanced_layout->setHorizontalSpacing(12);
        advanced_layout->setVerticalSpacing(7);
        m_search_label = new QLabel(QStringLiteral("目录搜索"));
        advanced_layout->addWidget(m_search_label, 0, 0);
        m_search_edit = new QLineEdit();
        m_search_edit->setPlaceholderText(QStringLiteral("可选：ASCII 或 UTF-16LE 文本"));
        advanced_layout->addWidget(m_search_edit, 0, 1, 1, 3);
        m_search_ignore_case = new QCheckBox(QStringLiteral("忽略大小写"));
        advanced_layout->addWidget(m_search_ignore_case, 0, 4);
        m_wxid_label = new QLabel(QStringLiteral("wxid"));
        advanced_layout->addWidget(m_wxid_label, 0, 5);
        m_wxid_edit = new QLineEdit();
        m_wxid_edit->setPlaceholderText(QStringLiteral("可选身份"));
        advanced_layout->addWidget(m_wxid_edit, 0, 6);

        m_directory_limits = new QCheckBox(QStringLiteral("自定义目录运行预算"));
        advanced_layout->addWidget(m_directory_limits, 1, 0, 1, 2);
        m_max_depth_label = new QLabel(QStringLiteral("最大深度"));
        advanced_layout->addWidget(m_max_depth_label, 1, 2);
        m_max_depth = new QSpinBox();
        m_max_depth->setRange(0, 1024);
        m_max_depth->setValue(8);
        advanced_layout->addWidget(m_max_depth, 1, 3);
        m_max_targets_label = new QLabel(QStringLiteral("运行目标数"));
        advanced_layout->addWidget(m_max_targets_label, 1, 4);
        m_max_runtime_targets = new QSpinBox();
        m_max_runtime_targets->setRange(1, 100000);
        m_max_runtime_targets->setValue(4);
        advanced_layout->addWidget(m_max_runtime_targets, 1, 5);
        m_run_all = new QCheckBox(QStringLiteral("运行全部确认目标"));
        advanced_layout->addWidget(m_run_all, 1, 6);

        m_total_budget_label = new QLabel(QStringLiteral("总运行预算"));
        advanced_layout->addWidget(m_total_budget_label, 2, 0);
        m_total_runtime_budget = new QSpinBox();
        m_total_runtime_budget->setRange(1, 86400);
        m_total_runtime_budget->setValue(45);
        m_total_runtime_budget->setSuffix(QStringLiteral(" 秒"));
        advanced_layout->addWidget(m_total_runtime_budget, 2, 1);
        m_artifact_limits = new QCheckBox(QStringLiteral("自定义工件预算"));
        advanced_layout->addWidget(m_artifact_limits, 2, 2, 1, 2);
        m_artifact_depth_label = new QLabel(QStringLiteral("工件深度"));
        advanced_layout->addWidget(m_artifact_depth_label, 2, 4);
        m_artifact_depth = new QSpinBox();
        m_artifact_depth->setRange(0, 32);
        m_artifact_depth->setValue(4);
        advanced_layout->addWidget(m_artifact_depth, 2, 5);
        m_run_all->setToolTip(QStringLiteral("目录运行模式下忽略优先级筛选，但仍受总预算约束。"));

        m_artifact_nodes_label = new QLabel(QStringLiteral("工件节点"));
        advanced_layout->addWidget(m_artifact_nodes_label, 3, 0);
        m_artifact_nodes = new QSpinBox();
        m_artifact_nodes->setRange(1, 1000000);
        m_artifact_nodes->setValue(1024);
        advanced_layout->addWidget(m_artifact_nodes, 3, 1);
        m_artifact_bytes_label = new QLabel(QStringLiteral("工件容量"));
        advanced_layout->addWidget(m_artifact_bytes_label, 3, 2);
        m_artifact_bytes = new QSpinBox();
        m_artifact_bytes->setRange(1, 1024 * 1024);
        m_artifact_bytes->setValue(512);
        m_artifact_bytes->setSuffix(QStringLiteral(" MiB"));
        advanced_layout->addWidget(m_artifact_bytes, 3, 3);
        m_artifact_root_label = new QLabel(QStringLiteral("工件目录"));
        advanced_layout->addWidget(m_artifact_root_label, 3, 4);
        m_artifact_root_edit = new QLineEdit();
        m_artifact_root_edit->setPlaceholderText(QStringLiteral("可选：单文件 product-owned 目录"));
        advanced_layout->addWidget(m_artifact_root_edit, 3, 5);
        m_choose_artifact_root = new QPushButton(QStringLiteral("选择…"));
        advanced_layout->addWidget(m_choose_artifact_root, 3, 6);
        advanced_layout->setColumnStretch(1, 1);
        advanced_layout->setColumnStretch(3, 1);
        advanced_layout->setColumnStretch(5, 1);
        m_settings_tabs->addTab(advanced_page, QStringLiteral("高级"));
        settings_layout->addWidget(m_settings_tabs);
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
            "QLineEdit, QSpinBox, QComboBox { background:#111b2d; color:#e5e7eb; border:1px solid #30435f; border-radius:5px; padding:6px; }"
            "QComboBox QAbstractItemView { background:#111b2d; color:#e5e7eb; selection-background-color:#1e497b; }"
            "QTabWidget::pane { border:1px solid #253b5a; border-radius:6px; background:#0f192b; }"
            "QTabBar::tab { background:#111b2d; color:#8fa4c2; padding:6px 14px; border:1px solid #253b5a; border-bottom:0; }"
            "QTabBar::tab:selected { background:#1b3357; color:#e5efff; }"
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
        connect(m_choose_output, &QPushButton::clicked, this, [this] { chooseOutput(); });
        connect(m_choose_artifact_root, &QPushButton::clicked, this, [this] { chooseArtifactRoot(); });
        connect(m_language, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) { m_english = index == 1; applyLanguage(); showSelected(); });
        connect(m_run, &QCheckBox::toggled, this, [this](bool checked) {
            m_apply->setEnabled(checked);
            m_runtime_mode->setEnabled(checked);
            m_run_all->setEnabled(checked);
            if (!checked) { m_apply->setChecked(false); return; }
            const auto result = QMessageBox::warning(this, m_english ? QStringLiteral("Confirm runtime analysis") : QStringLiteral("确认运行时分析"),
                m_english ? QStringLiteral("The sample will be executed for runtime evidence. Continue?") : QStringLiteral("将执行样本以收集运行时证据，确定继续吗？"),
                QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);
            if (result != QMessageBox::Ok) m_run->setChecked(false);
        });
        connect(m_apply, &QCheckBox::toggled, this, [this](bool checked) {
            if (checked && !m_run->isChecked()) { m_apply->setChecked(false); return; }
            if (checked) {
                const auto result = QMessageBox::warning(this, m_english ? QStringLiteral("Confirm write-back") : QStringLiteral("确认写回"),
                    m_english ? QStringLiteral("Write-back may modify files. Continue?") : QStringLiteral("写回可能修改文件，确定继续吗？"), QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);
                if (result != QMessageBox::Ok) m_apply->setChecked(false);
            }
        });
        connect(m_search_edit, &QLineEdit::textChanged, this, [this] { updateAdvancedState(); });
        connect(m_directory_limits, &QCheckBox::toggled, this, [this] { updateAdvancedState(); });
        connect(m_artifact_limits, &QCheckBox::toggled, this, [this] { updateAdvancedState(); });
        connect(m_open_report, &QPushButton::clicked, this, [this] { openReport(); });
        connect(m_open_output, &QPushButton::clicked, this, [this] { openOutput(); });
        connect(m_queue_table, &QTableWidget::itemSelectionChanged, this, [this] { showSelected(); });
        connect(m_queue_table, &QTableWidget::cellDoubleClicked, this, [this](int, int) { openReport(); });
        connect(m_filter_edit, &QLineEdit::textChanged, this, [this] { showSelected(); });
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
        updateAdvancedState();
    }

    void detectCli() {
        const QByteArray override_path = qgetenv("AUTO_REFIRST_CLI");
        if (!override_path.isEmpty()) {
            m_cli_path = QString::fromLocal8Bit(override_path);
            return;
        }
        const QString exe = QCoreApplication::applicationDirPath() + QDir::separator() +
#ifdef Q_OS_WIN
            QStringLiteral("auto-refirst.exe");
#else
            QStringLiteral("auto-refirst");
#endif
        if (QFileInfo(exe).isFile()) {
            m_cli_path = QDir::toNativeSeparators(exe);
            return;
        }
        const QString fromPath = QStandardPaths::findExecutable(QStringLiteral("auto-refirst"));
        m_cli_path = fromPath;
    }

    void applyLanguage() {
        m_title->setText(QStringLiteral("auto-refirst"));
        setWindowTitle(m_english ? QStringLiteral("auto-refirst  ·  Evidence workspace") : QStringLiteral("auto-refirst  ·  证据工作台"));
        m_subtitle->setText(m_english ? QStringLiteral("Static preparation workspace for unusual programs") : QStringLiteral("异常程序预处理工作台"));
        m_queue_box->setTitle(m_english ? QStringLiteral("Samples  ·  drop files or folders here") : QStringLiteral("样本队列  ·  拖放文件或目录到这里"));
        m_detail_box->setTitle(m_english ? QStringLiteral("Report") : QStringLiteral("报告"));
        m_settings->setTitle(m_english ? QStringLiteral("Analysis settings") : QStringLiteral("分析设置"));
        m_settings_tabs->setTabText(0, m_english ? QStringLiteral("Basic") : QStringLiteral("基础"));
        m_settings_tabs->setTabText(1, m_english ? QStringLiteral("Advanced") : QStringLiteral("高级"));
        m_output_label->setText(m_english ? QStringLiteral("Report folder") : QStringLiteral("报告目录"));
        m_choose_output->setText(m_english ? QStringLiteral("Browse…") : QStringLiteral("选择…"));
        m_timeout_label->setText(m_english ? QStringLiteral("Timeout") : QStringLiteral("单项超时"));
        m_safety->setText(m_english ? QStringLiteral("Static analysis is default; runtime and replacement require explicit action") : QStringLiteral("默认只做静态分析；运行时和写回均需主动开启"));
        m_add_file->setText(m_english ? QStringLiteral("Add files") : QStringLiteral("添加文件"));
        m_add_dir->setText(m_english ? QStringLiteral("Add folder") : QStringLiteral("添加目录"));
        m_clear->setText(m_english ? QStringLiteral("Clear") : QStringLiteral("清空"));
        m_start->setText(m_english ? QStringLiteral("Analyze") : QStringLiteral("开始分析"));
        m_cancel->setText(m_english ? QStringLiteral("Cancel") : QStringLiteral("取消"));
        m_open_report->setText(m_english ? QStringLiteral("Open JSON") : QStringLiteral("打开 JSON"));
        m_open_output->setText(m_english ? QStringLiteral("Open report folder") : QStringLiteral("打开报告目录"));
        m_extract->setText(m_english ? QStringLiteral("Expand static containers") : QStringLiteral("展开静态容器"));
        m_extract->setToolTip(m_english ? QStringLiteral("Add bounded static artifact expansion and heavier static analysis.") : QStringLiteral("增加有界静态工件展开和重型静态分析。"));
        m_recursive->setText(m_english ? QStringLiteral("Recursive artifact report") : QStringLiteral("递归工件报告"));
        m_recursive->setToolTip(m_english ? QStringLiteral("Emit recursive artifact reports; extracted children remain static-only.") : QStringLiteral("输出递归工件报告；递归子工件保持静态。"));
        m_run->setText(m_english ? QStringLiteral("Runtime analysis") : QStringLiteral("运行时分析"));
        m_run->setToolTip(m_english ? QStringLiteral("Off by default; enabling it asks for confirmation.") : QStringLiteral("默认关闭；启用前需要确认。"));
        m_apply->setText(m_english ? QStringLiteral("Allow replacement") : QStringLiteral("允许写回"));
        m_apply->setToolTip(m_english ? QStringLiteral("Allow validated replacement only after runtime analysis.") : QStringLiteral("仅在运行时分析后允许经过验证的写回。"));
        m_runtime_mode_label->setText(m_english ? QStringLiteral("Runtime mode") : QStringLiteral("运行模式"));
        const QStringList runtime_modes = m_english
            ? QStringList{QStringLiteral("Automatic deep analysis"), QStringLiteral("Trace compatibility"), QStringLiteral("Unpack compatibility"), QStringLiteral("Python probe compatibility")}
            : QStringList{QStringLiteral("自动深度分析"), QStringLiteral("Trace 兼容模式"), QStringLiteral("Unpack 兼容模式"), QStringLiteral("Python 探针兼容模式")};
        for (int i = 0; i < runtime_modes.size() && i < m_runtime_mode->count(); ++i) m_runtime_mode->setItemText(i, runtime_modes[i]);
        m_search_label->setText(m_english ? QStringLiteral("Directory search") : QStringLiteral("目录搜索"));
        m_search_edit->setPlaceholderText(m_english ? QStringLiteral("Optional ASCII or UTF-16LE text") : QStringLiteral("可选：ASCII 或 UTF-16LE 文本"));
        m_search_ignore_case->setText(m_english ? QStringLiteral("Ignore case") : QStringLiteral("忽略大小写"));
        m_wxid_label->setText(m_english ? QStringLiteral("wxid") : QStringLiteral("wxid"));
        m_wxid_edit->setPlaceholderText(m_english ? QStringLiteral("Optional identity") : QStringLiteral("可选身份"));
        m_directory_limits->setText(m_english ? QStringLiteral("Custom directory runtime budget") : QStringLiteral("自定义目录运行预算"));
        m_max_depth_label->setText(m_english ? QStringLiteral("Max depth") : QStringLiteral("最大深度"));
        m_max_targets_label->setText(m_english ? QStringLiteral("Runtime targets") : QStringLiteral("运行目标数"));
        m_run_all->setText(m_english ? QStringLiteral("Run every confirmed target") : QStringLiteral("运行全部确认目标"));
        m_run_all->setToolTip(m_english ? QStringLiteral("Run all confirmed directory targets within the total budget.") : QStringLiteral("在总预算内运行目录中所有已确认目标。"));
        m_total_budget_label->setText(m_english ? QStringLiteral("Total runtime budget") : QStringLiteral("总运行预算"));
        m_total_runtime_budget->setSuffix(m_english ? QStringLiteral(" s") : QStringLiteral(" 秒"));
        m_artifact_limits->setText(m_english ? QStringLiteral("Custom artifact budget") : QStringLiteral("自定义工件预算"));
        m_artifact_depth_label->setText(m_english ? QStringLiteral("Artifact depth") : QStringLiteral("工件深度"));
        m_artifact_nodes_label->setText(m_english ? QStringLiteral("Artifact nodes") : QStringLiteral("工件节点"));
        m_artifact_bytes_label->setText(m_english ? QStringLiteral("Artifact size") : QStringLiteral("工件容量"));
        m_artifact_bytes->setSuffix(m_english ? QStringLiteral(" MiB") : QStringLiteral(" MiB"));
        m_artifact_root_label->setText(m_english ? QStringLiteral("Artifact folder") : QStringLiteral("工件目录"));
        m_artifact_root_edit->setPlaceholderText(m_english ? QStringLiteral("Optional product-owned folder for one file") : QStringLiteral("可选：单文件 product-owned 目录"));
        m_choose_artifact_root->setText(m_english ? QStringLiteral("Browse…") : QStringLiteral("选择…"));
        m_queue_hint->setText(m_english ? QStringLiteral("Dropped items start automatically. Double-click a finished row to open its JSON report.") : QStringLiteral("拖放后会自动开始。双击已完成项打开 JSON 报告。"));
        m_filter_edit->setPlaceholderText(m_english ? QStringLiteral("Filter findings…") : QStringLiteral("筛选发现…"));
        if (m_queue_table->currentRow() < 0) m_summary->setText(m_english ? QStringLiteral("Select a row to view its summary") : QStringLiteral("选择一行查看摘要"));
        if (m_items.isEmpty()) m_progress->setFormat(m_english ? QStringLiteral("Waiting for samples") : QStringLiteral("等待样本"));
        m_queue_table->setHorizontalHeaderLabels(m_english
            ? QStringList{QStringLiteral("Sample"), QStringLiteral("Status"), QStringLiteral("Format"), QStringLiteral("Findings"), QStringLiteral("Report")}
            : QStringList{QStringLiteral("样本"), QStringLiteral("状态"), QStringLiteral("格式"), QStringLiteral("发现"), QStringLiteral("报告")});
        m_timeout->setSuffix(m_english ? QStringLiteral(" s") : QStringLiteral(" 秒"));
        for (int row = 0; row < m_items.size(); ++row) {
            const QString state = m_items[row].state;
            if (!m_items[row].report.isEmpty()) {
                renderSummary(m_items[row].report, m_items[row].format, m_items[row].evidence, m_items[row].detail);
                setCell(row, 2, m_items[row].format);
                setCell(row, 3, m_items[row].evidence);
            }
            QString shown = state;
            if (state == QStringLiteral("Queued")) shown = m_english ? QStringLiteral("Queued") : QStringLiteral("等待");
            else if (state == QStringLiteral("Running")) shown = m_english ? QStringLiteral("Analyzing…") : QStringLiteral("分析中…");
            else if (state == QStringLiteral("Done")) shown = m_english ? QStringLiteral("Complete") : QStringLiteral("完成");
            else if (state == QStringLiteral("Failed")) shown = m_english ? QStringLiteral("Failed") : QStringLiteral("失败");
            else if (state == QStringLiteral("Cancelled")) shown = m_english ? QStringLiteral("Cancelled") : QStringLiteral("已取消");
            if (state == QStringLiteral("Done") && m_items[row].evidence.contains(QStringLiteral("partial"), Qt::CaseInsensitive))
                shown = m_english ? QStringLiteral("Complete · partial") : QStringLiteral("完成 · 部分");
            setCell(row, 1, shown);
            if (state == QStringLiteral("Queued")) setCell(row, 2, m_english ? QStringLiteral("Pending") : QStringLiteral("待识别"));
        }
        updateAdvancedState();
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
        m_queue_table->setItem(row, 1, new QTableWidgetItem(m_english ? QStringLiteral("Queued") : QStringLiteral("等待")));
        m_queue_table->setItem(row, 2, new QTableWidgetItem(m_english ? QStringLiteral("Pending") : QStringLiteral("待识别")));
        m_queue_table->setItem(row, 3, new QTableWidgetItem(QStringLiteral("—")));
        m_queue_table->setItem(row, 4, new QTableWidgetItem(QStringLiteral("—")));
        return true;
    }

    void addFiles() {
        const auto files = QFileDialog::getOpenFileNames(this, m_english ? QStringLiteral("Choose sample files") : QStringLiteral("选择样本文件"));
        int added = 0;
        for (const auto& file : files) if (addPath(file)) ++added;
        if (added) {
            setStatus(QStringLiteral("已加入 %1 个样本，正在自动分析待处理项。").arg(added));
            startPending();
        }
    }

    void addDirectory() {
        const QString dir = QFileDialog::getExistingDirectory(this, m_english ? QStringLiteral("Choose sample folder") : QStringLiteral("选择样本目录"));
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
        m_summary->setText(m_english ? QStringLiteral("Select a row to view its summary") : QStringLiteral("选择一行查看摘要"));
        m_open_report->setEnabled(false);
        m_open_output->setEnabled(false);
        m_progress->setRange(0, 0);
        m_progress->setFormat(m_english ? QStringLiteral("Waiting for samples") : QStringLiteral("等待样本"));
        setStatus(QStringLiteral("队列已清空。"));
    }

    void chooseOutput() {
        const QString selected = QFileDialog::getExistingDirectory(this,
            m_english ? QStringLiteral("Choose report folder") : QStringLiteral("选择报告输出目录"), m_output_edit->text());
        if (!selected.isEmpty()) m_output_edit->setText(selected);
    }

    void chooseArtifactRoot() {
        const QString selected = QFileDialog::getExistingDirectory(this,
            m_english ? QStringLiteral("Choose artifact folder") : QStringLiteral("选择工件目录"),
            m_artifact_root_edit->text());
        if (!selected.isEmpty()) m_artifact_root_edit->setText(selected);
    }

    void updateAdvancedState() {
        const bool search = m_search_edit && !m_search_edit->text().trimmed().isEmpty();
        if (m_extract) m_extract->setEnabled(!search);
        if (m_recursive) m_recursive->setEnabled(!search);
        if (m_run) m_run->setEnabled(!search);
        if (m_apply) m_apply->setEnabled(!search && m_run->isChecked());
        if (m_runtime_mode) m_runtime_mode->setEnabled(!search && m_run->isChecked());
        if (m_run_all) m_run_all->setEnabled(!search && m_run->isChecked());
        if (m_artifact_root_edit) m_artifact_root_edit->setEnabled(!search);
        if (m_choose_artifact_root) m_choose_artifact_root->setEnabled(!search);
        if (m_artifact_limits) m_artifact_limits->setEnabled(!search);
        const bool directory_limits = m_directory_limits && m_directory_limits->isChecked();
        if (m_max_depth) m_max_depth->setEnabled(directory_limits);
        if (m_max_runtime_targets) m_max_runtime_targets->setEnabled(directory_limits);
        if (m_total_runtime_budget) m_total_runtime_budget->setEnabled(directory_limits);
        const bool artifact_limits = m_artifact_limits && m_artifact_limits->isChecked() && !search;
        if (m_artifact_depth) m_artifact_depth->setEnabled(artifact_limits);
        if (m_artifact_nodes) m_artifact_nodes->setEnabled(artifact_limits);
        if (m_artifact_bytes) m_artifact_bytes->setEnabled(artifact_limits);
        if (search && m_run->isChecked()) {
            m_run->setChecked(false);
            m_apply->setChecked(false);
        }
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
            setCell(i, 1, m_english ? QStringLiteral("Queued") : QStringLiteral("等待"));
            setCell(i, 2, m_english ? QStringLiteral("Pending") : QStringLiteral("待识别"));
            setCell(i, 3, QStringLiteral("—"));
            setCell(i, 4, QStringLiteral("—"));
            m_items[i].state = QStringLiteral("Queued");
            m_items[i].format.clear();
            m_items[i].evidence.clear();
            m_items[i].detail.clear();
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
        setCell(m_current, 1, m_english ? QStringLiteral("Analyzing…") : QStringLiteral("分析中…"));
        const QString program = m_cli_path.trimmed();
        if (program.isEmpty()) {
            m_start_error = m_english ? QStringLiteral("auto-refirst was not found next to the GUI") : QStringLiteral("未找到同目录 auto-refirst");
            finishWithoutProcess();
            return;
        }
        QStringList args;
        const QString search = m_search_edit->text().trimmed();
        args << m_items[m_current].path << QStringLiteral("--json") << QStringLiteral("--json-errors")
             << QStringLiteral("--report-lang=%1").arg(m_english ? QStringLiteral("en") : QStringLiteral("zh"));
        if (search.isEmpty()) args << QStringLiteral("--json-envelope");
        else {
            args << QStringLiteral("--search=%1").arg(search);
            if (m_search_ignore_case->isChecked()) args << QStringLiteral("--search-ignore-case");
        }
        if (search.isEmpty() && m_extract->isChecked()) args << QStringLiteral("--extract");
        if (search.isEmpty() && m_recursive->isChecked()) args << QStringLiteral("--recursive");
        if (m_run->isChecked()) {
            if (search.isEmpty()) {
                const QString mode = m_runtime_mode->currentData().toString();
                args << (mode.isEmpty() ? QStringLiteral("--run") : QStringLiteral("--run=%1").arg(mode));
                if (m_apply->isChecked()) args << QStringLiteral("--apply");
                if (m_run_all->isChecked()) args << QStringLiteral("--run-all");
            }
        }
        args << QStringLiteral("--timeout=%1").arg(m_timeout->value() * 1000);
        if (m_directory_limits->isChecked()) {
            args << QStringLiteral("--max-depth=%1").arg(m_max_depth->value())
                 << QStringLiteral("--max-runtime-targets=%1").arg(m_max_runtime_targets->value())
                 << QStringLiteral("--total-runtime-budget=%1").arg(m_total_runtime_budget->value() * 1000);
        }
        if (search.isEmpty() && m_artifact_limits->isChecked()) {
            args << QStringLiteral("--artifact-depth=%1").arg(m_artifact_depth->value())
                 << QStringLiteral("--artifact-nodes=%1").arg(m_artifact_nodes->value())
                 << QStringLiteral("--artifact-bytes=%1").arg(static_cast<qint64>(m_artifact_bytes->value()) * 1024 * 1024);
        }
        const QString artifact_root = m_artifact_root_edit->text().trimmed();
        const QFileInfo input_info(m_items[m_current].path);
        if (!artifact_root.isEmpty() && (search.isEmpty() ? (!input_info.isFile() || (m_extract->isChecked() && m_recursive->isChecked())) : true)) {
            m_start_error = m_english
                ? QStringLiteral("The artifact folder is valid only for one file without recursive extraction.")
                : QStringLiteral("工件目录只适用于单文件且不能与递归展开同时使用。");
            finishWithoutProcess();
            return;
        }
        if (!artifact_root.isEmpty()) {
            args << QStringLiteral("--artifact-root=%1").arg(artifact_root);
        }
        const QString wxid = m_wxid_edit->text().trimmed();
        if (!wxid.isEmpty()) args << QStringLiteral("--wxid=%1").arg(wxid);
        m_process->setProgram(program);
        m_process->setArguments(args);
        const QFileInfo program_info(program);
        if (program_info.isAbsolute() && program_info.isFile())
            m_process->setWorkingDirectory(program_info.absolutePath());
#ifdef Q_OS_WIN
        m_process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* arguments) {
            arguments->flags |= CREATE_NO_WINDOW;
        });
#endif
        m_process->start();
        if (!m_process->waitForStarted(2000)) {
            m_start_error = m_process->errorString().isEmpty()
                ? (m_english ? QStringLiteral("The CLI could not be started.") : QStringLiteral("无法启动 CLI")) : m_process->errorString();
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
            m_start_error = m_english
                ? QStringLiteral("The report exceeded the 64 MiB GUI display limit; use the CLI for the full output.")
                : QStringLiteral("报告超过 GUI 的 64 MiB 展示上限；请直接使用 CLI 保存完整输出");
            m_process->kill();
        }
    }

    void consumeError() {
        if (m_current >= 0) m_stderr += m_process->readAllStandardError();
        if (m_stderr.size() > kUiErrorCap) {
            m_stderr.truncate(static_cast<int>(kUiErrorCap));
            if (m_start_error.isEmpty()) m_start_error = m_english
                ? QStringLiteral("CLI diagnostics exceeded the 4 MiB GUI limit.")
                : QStringLiteral("CLI stderr 超过 GUI 的 4 MiB 错误输出上限");
            if (m_process->state() != QProcess::NotRunning) m_process->kill();
        }
    }

    void processTimedOut() {
        if (m_current < 0 || m_process->state() == QProcess::NotRunning) return;
        m_timed_out = true;
        m_start_error = m_english
            ? QStringLiteral("The item exceeded the %1 second timeout and was stopped.").arg(m_timeout->value())
            : QStringLiteral("单项分析超过 %1 秒，已终止进程").arg(m_timeout->value());
        m_process->kill();
    }

    QJsonObject makeSearchReport() const {
        QJsonObject root;
        root.insert(QStringLiteral("input"), m_items[m_current].path);
        root.insert(QStringLiteral("report_schema_version"), QStringLiteral("1.0"));
        QJsonObject format;
        format.insert(QStringLiteral("kind"), QStringLiteral("SEARCH"));
        root.insert(QStringLiteral("format"), format);
        root.insert(QStringLiteral("search"), m_search_edit->text().trimmed());
        root.insert(QStringLiteral("search_ignore_case"), m_search_ignore_case->isChecked());
        QJsonArray hits;
        QJsonArray findings;
        const auto lines = QString::fromUtf8(m_stdout).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (const auto& line : lines) {
            QJsonParseError error{};
            const QJsonDocument doc = QJsonDocument::fromJson(line.toUtf8(), &error);
            if (!doc.isObject()) continue;
            const QJsonObject hit = doc.object();
            hits.push_back(hit);
            if (findings.size() >= 128) continue;
            QJsonObject finding;
            finding.insert(QStringLiteral("family"), QStringLiteral("Directory text search"));
            finding.insert(QStringLiteral("variant"), hit.value(QStringLiteral("encoding")).toString());
            finding.insert(QStringLiteral("state"), QStringLiteral("CONFIRMED"));
            QJsonArray evidence;
            evidence.push_back(QStringLiteral("match at %1:%2").arg(hit.value(QStringLiteral("file")).toString(), QString::number(hit.value(QStringLiteral("offset")).toInt())));
            finding.insert(QStringLiteral("evidence"), evidence);
            QJsonObject fields;
            fields.insert(QStringLiteral("file"), hit.value(QStringLiteral("file")));
            fields.insert(QStringLiteral("offset"), hit.value(QStringLiteral("offset")));
            fields.insert(QStringLiteral("context"), hit.value(QStringLiteral("context")));
            finding.insert(QStringLiteral("fields"), fields);
            findings.push_back(finding);
        }
        root.insert(QStringLiteral("search_hits"), hits);
        root.insert(QStringLiteral("findings"), findings);
        root.insert(QStringLiteral("search_match_count"), hits.size());
        root.insert(QStringLiteral("search_display_limited"), hits.size() > 128);
        return root;
    }

    void cancelAnalysis() {
        if (m_current < 0) return;
        m_cancel_requested = true;
        for (int i = 0; i < m_items.size(); ++i) {
            if (m_items[i].state == QStringLiteral("Queued")) {
                m_items[i].state = QStringLiteral("Cancelled");
                setCell(i, 1, m_english ? QStringLiteral("Cancelled") : QStringLiteral("已取消"));
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
            setCell(row, 1, m_english ? QStringLiteral("Cancelled") : QStringLiteral("已取消"));
        } else if (m_timed_out || !m_start_error.isEmpty()) {
            finishFailure(row, m_timed_out ? m_start_error : m_start_error);
        } else if (exit_status != QProcess::NormalExit || (exit_code != 0 && !(m_search_edit && !m_search_edit->text().trimmed().isEmpty() && exit_code == 1))) {
            QString message = parseErrorMessage(m_stderr);
            if (message.isEmpty()) message = QString::fromUtf8(m_stderr).trimmed();
            if (message.isEmpty()) message = QStringLiteral("CLI 退出码 %1").arg(exit_code);
            finishFailure(row, message);
        } else {
            const bool search_mode = m_search_edit && !m_search_edit->text().trimmed().isEmpty();
            QJsonParseError parse_error{};
            const QJsonDocument document = search_mode ? QJsonDocument() : QJsonDocument::fromJson(m_stdout, &parse_error);
            if (!search_mode && !document.isObject()) {
                finishFailure(row, QStringLiteral("CLI 输出不是 JSON object：%1").arg(parse_error.errorString()));
            } else {
                const QJsonObject object = search_mode ? makeSearchReport() : document.object();
                const QByteArray report_output = search_mode
                    ? QJsonDocument(object).toJson(QJsonDocument::Indented)
                    : m_stdout;
                QString report_error;
                const QString report_path = writeReport(m_items[row], report_output, report_error);
                if (report_path.isEmpty()) {
                    finishFailure(row, report_error);
                } else {
                    m_items[row].report = object;
                    m_items[row].report_path = report_path;
                    m_items[row].state = QStringLiteral("Done");
                    renderSummary(object, m_items[row].format, m_items[row].evidence, m_items[row].detail);
                    setCell(row, 1, m_items[row].evidence.contains(QStringLiteral("partial"), Qt::CaseInsensitive)
                        ? (m_english ? QStringLiteral("Complete · partial") : QStringLiteral("完成 · 部分"))
                        : (m_english ? QStringLiteral("Complete") : QStringLiteral("完成")));
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
            setCell(row, 1, m_english ? QStringLiteral("Cancelled") : QStringLiteral("已取消"));
        } else {
            finishFailure(row, m_start_error.isEmpty()
                ? (m_english ? QStringLiteral("The CLI could not be started.") : QStringLiteral("无法启动 CLI")) : m_start_error);
        }
        ++m_completed;
        m_progress->setValue(terminalCount());
        m_current = -1;
        maybeFinishAutomation();
        QTimer::singleShot(0, this, [this] { startNext(); });
    }

    void finishFailure(int row, const QString& message) {
        m_items[row].state = QStringLiteral("Failed");
        const QString title = m_english ? QStringLiteral("Analysis failed") : QStringLiteral("分析失败");
        m_items[row].detail = QStringLiteral("%1\n\n%2").arg(title, message);
        setCell(row, 1, m_english ? QStringLiteral("Failed") : QStringLiteral("失败"));
        setCell(row, 2, QStringLiteral("—"));
        setCell(row, 3, m_english ? QStringLiteral("Open details") : QStringLiteral("查看详情"));
        setCell(row, 4, QStringLiteral("—"));
        showSelectedIf(row);
        setStatus(QStringLiteral("分析失败：%1").arg(message));
    }

    QString writeReport(const QueueItem& item, const QByteArray& output, QString& error) const {
        QString directory = m_output_edit->text().trimmed();
        if (directory.isEmpty()) {
            error = m_english ? QStringLiteral("The report folder is empty.") : QStringLiteral("报告目录为空");
            return {};
        }
        QDir out(directory);
        if (!out.mkpath(QStringLiteral("."))) {
            error = m_english ? QStringLiteral("Could not create the report folder: %1").arg(directory) : QStringLiteral("无法创建报告目录：%1").arg(directory);
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
            error = m_english ? QStringLiteral("Could not write the report: %1").arg(file.errorString()) : QStringLiteral("无法写入报告：%1").arg(file.errorString());
            return {};
        }
        if (file.write(output) != output.size()) {
            error = m_english ? QStringLiteral("The report was written incompletely: %1").arg(file.errorString()) : QStringLiteral("报告写入不完整：%1").arg(file.errorString());
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

    bool familyMatch(const QJsonObject& finding, const QString& filter) const {
        const QString needle = filter.toCaseFolded();
        QString haystack = finding.value(QStringLiteral("family")).toString() + QStringLiteral(" ")
            + finding.value(QStringLiteral("variant")).toString() + QStringLiteral(" ")
            + finding.value(QStringLiteral("kind")).toString();
        for (const auto& value : finding.value(QStringLiteral("evidence")).toArray()) haystack += QStringLiteral(" ") + value.toString();
        return haystack.toCaseFolded().contains(needle);
    }

    QString stateLabel(const QString& raw) const {
        const QString state = stateText(raw);
        if (m_english) return state;
        if (state == QStringLiteral("CONFIRMED")) return QStringLiteral("已确认");
        if (state == QStringLiteral("LIKELY")) return QStringLiteral("可能");
        if (state == QStringLiteral("SUSPECTED") || state == QStringLiteral("ROUTE_HINT")) return QStringLiteral("待复核");
        if (state == QStringLiteral("PARTIAL")) return QStringLiteral("部分结果");
        if (state == QStringLiteral("FAILED")) return QStringLiteral("失败");
        if (state == QStringLiteral("LOCATED_NOT_MATERIALIZED")) return QStringLiteral("已定位，未展开");
        return state;
    }

    QString familyLabel(const QString& raw) const {
        if (m_english || raw.isEmpty()) return raw;
        struct Pair { const char* source; const char* translated; };
        static const Pair pairs[] = {
            {"Manual API resolver", "手工 API 解析器"},
            {"PE custom-loader surface", "PE 自定义加载器面"},
            {"PE delay-load imports", "PE 延迟加载导入"},
            {"PE export forwarders", "PE 导出转发"},
            {"CLR/native boundary", "CLR/原生边界"},
            {"CLR bootstrap import contract", "CLR 启动导入关系"},
            {"Managed dynamic loader surface", "托管动态加载面"},
            {"Native import hook surface", "原生导入 Hook 面"},
            {"Layered/polyglot format markers", "分层/多格式标记"},
            {"WebAssembly relocatable metadata", "WebAssembly 可重定位元数据"},
            {"Wasm import module dependency", "Wasm 导入模块依赖"},
            {"Automatic static artifact graph", "自动静态工件图"},
            {"Directory text search", "目录文本搜索"},
        };
        for (const auto& pair : pairs) if (raw == QLatin1String(pair.source)) return QString::fromUtf8(pair.translated);
        return raw;
    }

    QString variantLabel(const QString& raw) const {
        if (m_english || raw.isEmpty()) return raw;
        static const QHash<QString, QString> labels = {
            {QStringLiteral("x64 PEB/export/FNV1A32"), QStringLiteral("x64 PEB/导出/FNV1A32")},
            {QStringLiteral("x64 PEB/export/FNV1A32/no-pdata-entry-window"), QStringLiteral("x64 PEB/导出/FNV1A32/无 pdata 入口窗口")},
            {QStringLiteral("x64 PEB/export/modified-name-hash"), QStringLiteral("x64 PEB/导出/修改名称哈希")},
            {QStringLiteral("x64 PEB/export/modified-name-hash/no-pdata-entry-window"), QStringLiteral("x64 PEB/导出/修改名称哈希/无 pdata 入口窗口")},
        };
        const auto it = labels.constFind(raw);
        return it == labels.constEnd() ? raw : it.value();
    }

    QString cleanEvidence(const QString& raw) const {
        if (raw.isEmpty()) return {};
        if (raw.contains(QStringLiteral("execution_refusal"), Qt::CaseInsensitive)
            || raw.contains(QStringLiteral("negative_evidence"), Qt::CaseInsensitive)
            || raw.contains(QStringLiteral("static_only_runtime_not_performed"), Qt::CaseInsensitive)) {
            return m_english ? QStringLiteral("Static evidence") : QStringLiteral("静态证据");
        }
        QString text = raw;
        if (!m_english) {
            static const QHash<QString, QString> translations = {
                {QStringLiteral("x64 code reads PEB from GS:[0x60], follows loader-list state and iterates loaded module bases"), QStringLiteral("x64 通过 GS:[0x60] 读取 PEB，遍历加载器链表中的模块基址")},
                {QStringLiteral("the same bounded function validates PE signatures and walks IMAGE_EXPORT_DIRECTORY name/count, ordinal and function tables"), QStringLiteral("同一有界函数校验 PE 标记，并遍历 IMAGE_EXPORT_DIRECTORY 的名称、数量、序号和函数表")},
                {QStringLiteral("export names are hashed byte-wise with FNV-1a32 seed 0x811C9DC5 and prime 0x01000193 inside a bounded loop"), QStringLiteral("有界循环按字节使用 FNV-1a32（种子 0x811C9DC5、乘数 0x01000193）计算导出名称哈希")},
                {QStringLiteral("a bounded export-name loop applies arithmetic/bitwise hash-state updates; the exact name-hash algorithm is modified or unknown"), QStringLiteral("有界导出名称循环使用算术/位运算更新哈希状态，具体算法已被修改或无法确定")},
                {QStringLiteral("a hash match indexes name-ordinal/function tables and returns a module-base-relative export address"), QStringLiteral("哈希命中后索引名称、序号和函数表，返回相对模块基址的导出地址")},
                {QStringLiteral("the complete resolver shape was found in a bounded executable entry-section window"), QStringLiteral("在入口可执行节的有界窗口内恢复了完整解析器结构")},
            };
            const auto it = translations.constFind(text);
            if (it != translations.constEnd()) return it.value();
            text.replace(QStringLiteral("NOT_ATTEMPTED_STATIC_ONLY"), QStringLiteral("未执行运行时操作"));
            text.replace(QStringLiteral("CURRENT_INPUT_IMAGE"), QStringLiteral("当前输入映像"));
            text.replace(QStringLiteral("CURRENT_INPUT_FILE"), QStringLiteral("当前输入文件"));
        }
        return text;
    }

    QString actionLabel(const QString& raw) const {
        if (m_english || raw.isEmpty()) return raw;
        if (raw == QStringLiteral("extract:dotnet-symbols-and-types")) return QStringLiteral("导出 .NET 符号和类型信息。");
        if (raw == QStringLiteral("extract:dotnet-resources")) return QStringLiteral("展开 .NET 内嵌资源。");
        if (raw.contains(QStringLiteral("inspect user TypeDef methods"), Qt::CaseInsensitive)) return QStringLiteral("优先检查用户 TypeDef 方法和已恢复签名。");
        if (raw.contains(QStringLiteral("open in dnSpy/ILSpy/dotPeek"), Qt::CaseInsensitive)) return QStringLiteral("用 dnSpy、ILSpy 或 dotPeek 检查选定方法的 IL。");
        if (raw.contains(QStringLiteral("inspect embedded DLL/EXE/config payloads"), Qt::CaseInsensitive)) return QStringLiteral("先检查已展开的 DLL、EXE 和配置资源。");
        if (raw.contains(QStringLiteral("prioritize the selector target/fallthrough"), Qt::CaseInsensitive)) return QStringLiteral("先复核选择器的目标路径、顺落路径或返回值，再继续深入分析。");
        if (raw.contains(QStringLiteral("record the concrete runtime CPUID value"), Qt::CaseInsensitive)) return QStringLiteral("只有需要动态确认时，再记录实际运行时的 CPUID 值。");
        if (raw.contains(QStringLiteral("prioritize the gated path/value"), Qt::CaseInsensitive)) return QStringLiteral("先复核门控路径或返回值，再继续深入分析。");
        if (raw.contains(QStringLiteral("record concrete runtime XCR0"), Qt::CaseInsensitive)) return QStringLiteral("只有需要动态确认时，再记录实际运行时的 XCR0 值。");
        if (raw.contains(QStringLiteral("inspect the threshold-selected path/value"), Qt::CaseInsensitive)) return QStringLiteral("先检查阈值选择的路径或返回值，再判断其用途。");
        if (raw.contains(QStringLiteral("use dynamic timing"), Qt::CaseInsensitive)) return QStringLiteral("只有需要确认实际阈值结果时，再使用动态计时。");
        if (raw.contains(QStringLiteral("recreate the modified name-hash state"), Qt::CaseInsensitive)) return QStringLiteral("对照实际运行模块的导出表重建修改后的名称哈希状态。");
        if (raw.contains(QStringLiteral("prioritize recovered resolver callsites"), Qt::CaseInsensitive)) return QStringLiteral("先复核已恢复的解析器调用点，再确定 API 身份。");
        if (raw.contains(QStringLiteral("prioritize resolver function and recovered hash callsites"), Qt::CaseInsensitive)) return QStringLiteral("优先复核解析器函数和已恢复的哈希调用点。");
        if (raw.contains(QStringLiteral("map unknown hashes against exports"), Qt::CaseInsensitive)) return QStringLiteral("对照实际运行模块的导出表映射未知哈希，再确定 API 身份。");
        if (raw.contains(QStringLiteral("prioritize managed loader/reflection callsites"), Qt::CaseInsensitive)) return QStringLiteral("优先检查托管加载、反射调用点和内嵌资源。");
        if (raw.contains(QStringLiteral("trace the selected assembly/resource path"), Qt::CaseInsensitive)) return QStringLiteral("只有需要确认实际路径时，再跟踪选中的程序集或资源加载链。");
        if (raw.contains(QStringLiteral("inspect:iat-slot-writers-and-resolved-targets"), Qt::CaseInsensitive)) return QStringLiteral("检查 IAT 槽写入点和实际解析目标。");
        if (raw.contains(QStringLiteral("compare:disk-iAT-with-runtime-iAT"), Qt::CaseInsensitive)) return QStringLiteral("对比磁盘 IAT 与运行时 IAT 内容。");
        if (raw.contains(QStringLiteral("trace:loader-or-hook-initialization"), Qt::CaseInsensitive)) return QStringLiteral("只有需要运行时证据时，再跟踪加载器或 Hook 初始化链。");
        if (raw.contains(QStringLiteral("--run=python-probe"), Qt::CaseInsensitive)) return QStringLiteral("如需确认 CPython 编译器行为，可启用 --run=python-probe。");
        if (raw.contains(QStringLiteral("--run"), Qt::CaseInsensitive)) return QStringLiteral("如需运行时证据，可启用 --run。");
        if (raw.contains(QStringLiteral("--extract"), Qt::CaseInsensitive)) return QStringLiteral("如需完整容器或重型静态展开，可启用 --extract。");
        if (raw.contains(QStringLiteral("inspect"), Qt::CaseInsensitive) || raw.contains(QStringLiteral("review"), Qt::CaseInsensitive)) return QStringLiteral("复核 JSON 中的范围和证据。");
        if (raw.contains(QStringLiteral("sibling"), Qt::CaseInsensitive) || raw.contains(QStringLiteral("directory"), Qt::CaseInsensitive)) return QStringLiteral("结合同目录文件和关系报告继续定位。");
        return raw;
    }

    void renderSummary(const QJsonObject& root, QString& format, QString& evidence, QString& detail) const {
        QJsonArray reports;
        if (root.value(QStringLiteral("reports")).isArray()) reports = root.value(QStringLiteral("reports")).toArray();
        else reports.push_back(root);

        QStringList formats;
        QStringList lines;
        QStringList next_steps;
        int findings = 0;
        int confirmed = 0;
        int review = 0;
        bool partial = false;
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
                for (const auto& action : finding.value(QStringLiteral("suggested_actions")).toArray()) {
                    const QString text = action.toString().trimmed();
                    if (!text.isEmpty() && !next_steps.contains(text) && next_steps.size() < 6) next_steps.push_back(text);
                }
                const QString filter = m_filter_edit ? m_filter_edit->text().trimmed() : QString();
                if (lines.size() < 24 && (filter.isEmpty() || familyMatch(finding, filter))) {
                    const QString family = familyLabel(finding.value(QStringLiteral("family")).toString());
                    const QString variant = variantLabel(finding.value(QStringLiteral("variant")).toString());
                    const QJsonArray ev = finding.value(QStringLiteral("evidence")).toArray();
                    const QString evidence_text = ev.isEmpty() ? QString() : cleanEvidence(ev.first().toString());
                    QString label = family.isEmpty() ? finding.value(QStringLiteral("kind")).toString() : family;
                    if (!variant.isEmpty()) label += QStringLiteral(" / ") + variant;
                    lines.push_back(QStringLiteral("[%1] %2%3").arg(stateLabel(state), label, evidence_text.isEmpty() ? QString() : QStringLiteral("  — ") + evidence_text));
                }
            }
            const QJsonObject materialization = report.value(QStringLiteral("materialization")).toObject();
            if (materialization.value(QStringLiteral("partial")).toBool()) partial = true;
            const QJsonObject graph = report.value(QStringLiteral("artifact_graph")).toObject();
            if (graph.value(QStringLiteral("truncated")).toBool()) partial = true;
        }
        const QJsonObject directory = root.value(QStringLiteral("directory_summary")).toObject();
        if (!directory.isEmpty()) {
            partial = partial || directory.value(QStringLiteral("partial")).toBool();
            const auto ecosystems = directory.value(QStringLiteral("confirmed_ecosystems")).toArray();
            for (const auto& ecosystem : ecosystems) formats.push_back(ecosystem.toString());
            format = (m_english ? QStringLiteral("Directory · %1 files") : QStringLiteral("目录 · %1 个文件")).arg(directory.value(QStringLiteral("analyzed_files")).toInt());
        } else {
            const auto compact = uniqueStrings(formats);
            format = compact.isEmpty() ? (m_english ? QStringLiteral("unknown") : QStringLiteral("未知")) : compact.join(QStringLiteral(", "));
        }
        const QJsonObject rendering = root.value(QStringLiteral("report_rendering")).toObject();
        if (rendering.value(QStringLiteral("partial")).toBool()) partial = true;
        const QJsonObject artifacts = root.value(QStringLiteral("artifact_materialization")).toObject();
        if (artifacts.value(QStringLiteral("partial")).toBool()) partial = true;

        evidence = m_english
            ? QStringLiteral("%1 findings  ·  %2 confirmed  ·  %3 to review").arg(findings).arg(confirmed).arg(review)
            : QStringLiteral("%1 项发现  ·  %2 项已确认  ·  %3 项待复核").arg(findings).arg(confirmed).arg(review);
        if (partial) evidence += m_english ? QStringLiteral("  ·  limited") : QStringLiteral("  ·  部分输出");
        const QString input_label = directory.isEmpty() ? root.value(QStringLiteral("input")).toString() : directory.value(QStringLiteral("root")).toString();
        detail = (m_english ? QStringLiteral("INPUT\n%1\n\nFORMAT\n%2\n\nSUMMARY\n%3\n\n") : QStringLiteral("输入\n%1\n\n格式\n%2\n\n摘要\n%3\n\n")).arg(input_label, format, evidence);
        if (!next_steps.isEmpty()) {
            detail += m_english ? QStringLiteral("NEXT STEPS\n") : QStringLiteral("下一步\n");
            for (const auto& action : next_steps) detail += QStringLiteral("• ") + actionLabel(action) + QLatin1Char('\n');
            detail += QLatin1Char('\n');
        }
        detail += m_english ? QStringLiteral("FINDINGS\n") : QStringLiteral("发现\n");
        if (lines.isEmpty()) detail += m_english ? QStringLiteral("No findings match the filter.\n") : QStringLiteral("没有符合筛选条件的发现。\n");
        else detail += lines.join(QStringLiteral("\n")) + QLatin1Char('\n');
        detail += QStringLiteral("\n") + (m_english ? QStringLiteral("LIMITS\n") : QStringLiteral("限制\n"));
        if (partial) detail += m_english ? QStringLiteral("• Some output was limited; review the JSON report for the complete record.\n") : QStringLiteral("• 部分输出受限，请打开 JSON 查看完整记录。\n");
        if (!partial) detail += m_english ? QStringLiteral("• No output limits were reported.\n") : QStringLiteral("• 未报告输出限制。\n");
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
            QString state = item.state;
            if (item.state == QStringLiteral("Queued")) state = m_english ? QStringLiteral("Queued") : QStringLiteral("等待");
            else if (item.state == QStringLiteral("Running")) state = m_english ? QStringLiteral("Analyzing…") : QStringLiteral("分析中…");
            else if (item.state == QStringLiteral("Failed")) state = m_english ? QStringLiteral("Failed") : QStringLiteral("失败");
            else if (item.state == QStringLiteral("Cancelled")) state = m_english ? QStringLiteral("Cancelled") : QStringLiteral("已取消");
            m_summary->setText(QStringLiteral("%1  ·  %2").arg(shortPath(item.path), state));
            m_detail->setPlainText(item.detail.isEmpty() ? (m_english ? QStringLiteral("Waiting for analysis…") : QStringLiteral("等待分析结果…")) : item.detail);
        } else {
            QString next = item.detail.section(m_english ? QStringLiteral("NEXT STEPS\n") : QStringLiteral("下一步\n"), 1, 1).section(QLatin1Char('\n'), 0, 0).trimmed();
            QString headline = QStringLiteral("%1  ·  %2  ·  %3").arg(shortPath(item.path), item.format, item.evidence);
            if (!next.isEmpty()) headline += m_english ? QStringLiteral("  ·  Next: %1").arg(next) : QStringLiteral("  ·  下一步：%1").arg(next);
            m_summary->setText(headline);
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

    void setStatus(const QString& status) {
        if (!m_english) { m_status->setText(status); return; }
        if (status.contains(QStringLiteral("已从启动参数加入"))) { m_status->setText(QStringLiteral("Startup items queued; analysis will begin.")); return; }
        if (status.contains(QStringLiteral("已忽略非本地拖放项"))) { m_status->setText(QStringLiteral("Ignored a non-local drop.")); return; }
        if (status.contains(QStringLiteral("已加入"))) { m_status->setText(QStringLiteral("Items queued; analysis will begin.")); return; }
        if (status.contains(QStringLiteral("无法加入"))) { m_status->setText(QStringLiteral("The item could not be added.")); return; }
        if (status.contains(QStringLiteral("分析进行中"))) { m_status->setText(QStringLiteral("Finish or cancel the current analysis first.")); return; }
        if (status.contains(QStringLiteral("队列已清空"))) { m_status->setText(QStringLiteral("Queue cleared.")); return; }
        if (status.contains(QStringLiteral("队列为空"))) { m_status->setText(QStringLiteral("Queue is empty.")); return; }
        if (status.contains(QStringLiteral("分析已取消"))) { m_status->setText(QStringLiteral("Cancelled; completed reports remain available.")); return; }
        if (status.contains(QStringLiteral("队列分析完成"))) { m_status->setText(QStringLiteral("Queue complete.")); return; }
        if (status.contains(QStringLiteral("正在分析"))) { m_status->setText(QStringLiteral("Analyzing…")); return; }
        if (status.contains(QStringLiteral("已完成"))) { m_status->setText(QStringLiteral("Complete")); return; }
        if (status.contains(QStringLiteral("分析失败"))) { m_status->setText(QStringLiteral("Analysis failed")); return; }
        if (status.contains(QStringLiteral("已取消"))) { m_status->setText(QStringLiteral("Cancelled")); return; }
        m_status->setText(status);
    }

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
    QGroupBox* m_queue_box = nullptr;
    QGroupBox* m_detail_box = nullptr;
    QGroupBox* m_settings = nullptr;
    QTabWidget* m_settings_tabs = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QLabel* m_queue_hint = nullptr;
    QLabel* m_output_label = nullptr;
    QLabel* m_timeout_label = nullptr;
    QLabel* m_runtime_mode_label = nullptr;
    QLabel* m_search_label = nullptr;
    QLabel* m_wxid_label = nullptr;
    QLabel* m_max_depth_label = nullptr;
    QLabel* m_max_targets_label = nullptr;
    QLabel* m_total_budget_label = nullptr;
    QLabel* m_artifact_depth_label = nullptr;
    QLabel* m_artifact_nodes_label = nullptr;
    QLabel* m_artifact_bytes_label = nullptr;
    QLabel* m_artifact_root_label = nullptr;
    QLabel* m_safety = nullptr;
    QTextEdit* m_detail = nullptr;
    QLineEdit* m_filter_edit = nullptr;
    QLabel* m_summary = nullptr;
    QLabel* m_status = nullptr;
    QProgressBar* m_progress = nullptr;
    QString m_cli_path;
    QLineEdit* m_output_edit = nullptr;
    QLineEdit* m_search_edit = nullptr;
    QLineEdit* m_wxid_edit = nullptr;
    QLineEdit* m_artifact_root_edit = nullptr;
    QSpinBox* m_timeout = nullptr;
    QSpinBox* m_max_depth = nullptr;
    QSpinBox* m_max_runtime_targets = nullptr;
    QSpinBox* m_total_runtime_budget = nullptr;
    QSpinBox* m_artifact_depth = nullptr;
    QSpinBox* m_artifact_nodes = nullptr;
    QSpinBox* m_artifact_bytes = nullptr;
    QCheckBox* m_extract = nullptr;
    QCheckBox* m_recursive = nullptr;
    QCheckBox* m_run = nullptr;
    QCheckBox* m_apply = nullptr;
    QCheckBox* m_run_all = nullptr;
    QCheckBox* m_search_ignore_case = nullptr;
    QCheckBox* m_directory_limits = nullptr;
    QCheckBox* m_artifact_limits = nullptr;
    QComboBox* m_runtime_mode = nullptr;
    QComboBox* m_language = nullptr;
    QPushButton* m_add_file = nullptr;
    QPushButton* m_add_dir = nullptr;
    QPushButton* m_clear = nullptr;
    QPushButton* m_start = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_choose_output = nullptr;
    QPushButton* m_choose_artifact_root = nullptr;
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
    bool m_english = false;
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
