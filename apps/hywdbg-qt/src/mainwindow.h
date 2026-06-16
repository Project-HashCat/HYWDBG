#pragma once
#include "global.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override;

private:
    // daemon state
    QProcess*     daemon              = nullptr;
    QTcpSocket*   rpcSocket           = nullptr;
    int           rpcId               = 1;
    QString       selectedBackendKind = QStringLiteral("titan");
    QString       rip;
    QString       rsp;
    QSet<QString> activeBpAddrs;
    bool          disasmFetchingMore  = false;

    // Patches
    struct PatchRecord {
        QString addr;
        QString origBytes;
        QString newBytes;
    };
    QMap<QString, PatchRecord> patches;

    // command history (feature 1)
    QStringList   cmdHistory;
    int           cmdHistoryIdx       = -1;

    // user data (persistent)
    QMap<QString, QString> userComments;
    QMap<QString, QString> userLabels;
    QSet<QString> bookmarks;
    void loadProject();
    void saveProject();
    void addBookmark(const QString& addr);
    void removeBookmark(const QString& addr);
    void editComment(const QString& addr);
    void editLabel(const QString& addr);

    // register change tracking (feature 3)
    QMap<QString, QString> prevRegValues;

    // widgets
    QComboBox*      backendCombo  = nullptr;
    QLabel*         statusLabel   = nullptr;
    QLabel*         ripLabel      = nullptr;
    QLabel*         pidLabel      = nullptr;
    QLabel*         backendLabel  = nullptr;
    QTableWidget*   disasmTable   = nullptr;
    QLineEdit*      disasmAddrBar = nullptr;
    QTableWidget*   regTable      = nullptr;
    QTableWidget*   memView       = nullptr;
    QLineEdit*      memAddrBar    = nullptr;
    QLineEdit*      memLenBar     = nullptr;
    QTableWidget*   bpTable       = nullptr;
    QTableWidget*   modTable      = nullptr;
    QTableWidget*   thrTable      = nullptr;
    QTableWidget*   stackTable    = nullptr;
    QTableWidget*   stackMemTable = nullptr;
    QTableWidget*   wpTable       = nullptr;
    QTableWidget*   memMapTable   = nullptr;
    QTableWidget*   patchTable    = nullptr;
    QTableWidget*   searchTable   = nullptr;
    QTableWidget*   bookmarkTable = nullptr;
    QTextEdit*      logView       = nullptr;
    QLineEdit*      cmdBar        = nullptr;

    QPushButton*    runBtn        = nullptr;
    QPushButton*    pauseBtn      = nullptr;

    void setDebugState(const QString& state, const QString& details = QString());

    // setup
    void applyDarkTheme();
    void buildMenu();
    void buildToolBar();
    void buildCentralWidget();
    void buildDocks();

    // helpers
    QTableWidget*     makeTable(const QStringList& headers);
    QDockWidget*      makeDock(const QString& title, Qt::DockWidgetArea area);
    static QTableWidgetItem* tableItem(const QString& text,
                                        const QColor& fg = QColor(0xD4, 0xD4, 0xD4),
                                        bool bold = false);
    void setStatus(const QString& msg);

    // daemon / RPC
    void startDaemon();
    void shutdownDaemon();
    QJsonValue rpc(const QString& method, const QJsonObject& params);

    // logging
    void log(const QString& msg, LogKind kind = LogKind::Info);

    // disasm helpers
    static QString mnemonicCategory(const QString& m);
    static QColor  mnemonicColor(const QString& cat);
    void addDisasmRow(int row,
                      const QString& addrFmt,
                      const QString& bytesStr,
                      const QString& mnemonic,
                      const QString& cat,
                      const QString& operands,
                      const QString& comment,
                      bool isRip,
                      bool hasBp);
    void updateDisasmRowHighlight(int row, bool isRip, bool hasBp);

    // symbol resolution - must come before refreshDisasm
    QString resolveToAddr(const QString& expr);

    // refresh / navigation
    void refreshDisasm(const QString& addr);
    void appendDisasm(const QString& fromAddr);
    void refreshRegs();
    void refreshModules();
    void refreshThreads();
    void refreshCallStack();
    void refreshBpList();
    void refreshMem();
    void refreshStack();
    void refreshMemoryMap();
    void refreshPatchesList();
    void refreshAll();

    // BP / run
    void toggleBpAt(const QString& rawAddr);
    void toggleHwBpAt(const QString& rawAddr, const QString& kind);
    void runToAddr(const QString& addr);
    void formatEventDetail(const QJsonObject& res);

    // NOP out helper (feature 10)
    void nopOutAt(const QString& addr, int count);
    void editMemByte(int row, int col, const QString& hexStr);

    // Patches
    void recordPatch(const QString& addr, const QString& origBytes, const QString& newBytes);
    void revertPatch(const QString& addr);

    // Attach dialog (feature 6)
    void showAttachDialog();

    // Search dialog
    void showSearchDialog();

    // command bar
    void runCommand(const QString& line);
};
