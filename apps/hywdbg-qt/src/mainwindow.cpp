#include "mainwindow.h"
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("HYWDbg"));
    resize(1600, 960);
    applyDarkTheme();
    buildMenu();
    buildToolBar();
    buildCentralWidget();
    buildDocks();

    statusLabel = new QLabel(this);
    statusBar()->addWidget(statusLabel, 1);
    
    ripLabel = new QLabel(QStringLiteral("RIP: ???"), this);
    ripLabel->setStyleSheet(QStringLiteral("color: #00D4FF;"));
    pidLabel = new QLabel(QStringLiteral("PID: none"), this);
    pidLabel->setStyleSheet(QStringLiteral("color: #E8C040;"));
    backendLabel = new QLabel(QStringLiteral("Backend: none"), this);
    backendLabel->setStyleSheet(QStringLiteral("color: #40C870;"));

    statusBar()->addPermanentWidget(ripLabel);
    statusBar()->addPermanentWidget(new QLabel(QStringLiteral(" | ")));
    statusBar()->addPermanentWidget(pidLabel);
    statusBar()->addPermanentWidget(new QLabel(QStringLiteral(" | ")));
    statusBar()->addPermanentWidget(backendLabel);

    QShortcut* f5 = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(f5, &QShortcut::activated, this, [this]() { runCommand(QStringLiteral("go")); });

    QShortcut* f6 = new QShortcut(QKeySequence(Qt::Key_F6), this);
    connect(f6, &QShortcut::activated, this, [this]() { runCommand(QStringLiteral("pause")); });

    QShortcut* f7 = new QShortcut(QKeySequence(Qt::Key_F7), this);
    connect(f7, &QShortcut::activated, this, [this]() { runCommand(QStringLiteral("si")); });

    QShortcut* f8 = new QShortcut(QKeySequence(Qt::Key_F8), this);
    connect(f8, &QShortcut::activated, this, [this]() { runCommand(QStringLiteral("so")); });

    QShortcut* f9 = new QShortcut(QKeySequence(Qt::Key_F9), this);
    connect(f9, &QShortcut::activated, this, [this]() { runCommand(QStringLiteral("sout")); });

    QShortcut* ctrlG = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_G), this);
    connect(ctrlG, &QShortcut::activated, this, [this]() {
        bool ok;
        QString text = QInputDialog::getText(this, QStringLiteral("Goto Address"), QStringLiteral("Address (hex):"), QLineEdit::Normal, QString(), &ok);
        if (ok && !text.isEmpty()) {
            refreshDisasm(text);
        }
    });

    QShortcut* ctrlR = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_R), this);
    connect(ctrlR, &QShortcut::activated, this, [this]() { refreshAll(); });

    QShortcut* ctrlF = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_F), this);
    connect(ctrlF, &QShortcut::activated, this, [this]() { showSearchDialog(); });

    loadProject();
}

MainWindow::~MainWindow()
{
    shutdownDaemon();
}

void MainWindow::applyDarkTheme()
{
    QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette p;
    p.setColor(QPalette::Window,          QColor(0x1E, 0x1E, 0x1E));
    p.setColor(QPalette::WindowText,      QColor(0xD4, 0xD4, 0xD4));
    p.setColor(QPalette::Base,            QColor(0x12, 0x12, 0x12));
    p.setColor(QPalette::AlternateBase,   QColor(0x1A, 0x1A, 0x1A));
    p.setColor(QPalette::ToolTipBase,     QColor(0x25, 0x25, 0x25));
    p.setColor(QPalette::ToolTipText,     QColor(0xD4, 0xD4, 0xD4));
    p.setColor(QPalette::Text,            QColor(0xD4, 0xD4, 0xD4));
    p.setColor(QPalette::Button,          QColor(0x2D, 0x2D, 0x2D));
    p.setColor(QPalette::ButtonText,      QColor(0xD4, 0xD4, 0xD4));
    p.setColor(QPalette::BrightText,      Qt::red);
    p.setColor(QPalette::Link,            QColor(0x58, 0xA8, 0xF8));
    p.setColor(QPalette::Highlight,       QColor(0x26, 0x4F, 0x78));
    p.setColor(QPalette::HighlightedText, QColor(0xD4, 0xD4, 0xD4));
    p.setColor(QPalette::Disabled, QPalette::Text,       QColor(0x60, 0x60, 0x60));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(0x60, 0x60, 0x60));
    QApplication::setPalette(p);

    const QString qss = QStringLiteral(
        "QMainWindow {"
        "  background: #1E1E1E;"
        "}"
        "QMenuBar {"
        "  background: #252526;"
        "  color: #D4D4D4;"
        "  border-bottom: 1px solid #3C3C3C;"
        "}"
        "QMenuBar::item:selected {"
        "  background: #264F78;"
        "}"
        "QMenu {"
        "  background: #252526;"
        "  color: #D4D4D4;"
        "  border: 1px solid #3C3C3C;"
        "}"
        "QMenu::item:selected {"
        "  background: #264F78;"
        "}"
        "QToolBar {"
        "  background: #2D2D2D;"
        "  border-bottom: 1px solid #3C3C3C;"
        "  spacing: 3px;"
        "}"
        "QPushButton {"
        "  background: #2D2D2D;"
        "  color: #D4D4D4;"
        "  border: 1px solid #3C3C3C;"
        "  border-radius: 3px;"
        "  padding: 3px 8px;"
        "}"
        "QPushButton:hover {"
        "  background: #3A3A3A;"
        "  border-color: #555555;"
        "}"
        "QPushButton:pressed {"
        "  background: #264F78;"
        "}"
        "QLineEdit {"
        "  background: #1A1A1A;"
        "  color: #D4D4D4;"
        "  border: 1px solid #3C3C3C;"
        "  border-radius: 2px;"
        "  padding: 2px 4px;"
        "  selection-background-color: #264F78;"
        "}"
        "QTableWidget {"
        "  background: #121212;"
        "  color: #D4D4D4;"
        "  gridline-color: #1E1E1E;"
        "  border: none;"
        "  selection-background-color: #264F78;"
        "  selection-color: #D4D4D4;"
        "}"
        "QHeaderView::section {"
        "  background: #252526;"
        "  color: #9CDCFE;"
        "  border: none;"
        "  border-bottom: 1px solid #3C3C3C;"
        "  padding: 2px 4px;"
        "  font-weight: bold;"
        "}"
        "QPlainTextEdit {"
        "  background: #121212;"
        "  color: #D4D4D4;"
        "  border: none;"
        "  selection-background-color: #264F78;"
        "}"
        "QTextEdit {"
        "  background: #0E0E0E;"
        "  color: #D4D4D4;"
        "  border: none;"
        "  selection-background-color: #264F78;"
        "}"
        "QScrollBar:vertical {"
        "  background: #1E1E1E;"
        "  width: 10px;"
        "  margin: 0;"
        "}"
        "QScrollBar::handle:vertical {"
        "  background: #3C3C3C;"
        "  min-height: 20px;"
        "  border-radius: 5px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        "  height: 0;"
        "}"
        "QScrollBar:horizontal {"
        "  background: #1E1E1E;"
        "  height: 10px;"
        "  margin: 0;"
        "}"
        "QScrollBar::handle:horizontal {"
        "  background: #3C3C3C;"
        "  min-width: 20px;"
        "  border-radius: 5px;"
        "}"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {"
        "  width: 0;"
        "}"
        "QDockWidget {"
        "  color: #D4D4D4;"
        "}"
        "QDockWidget::title {"
        "  background: #252526;"
        "  padding-left: 6px;"
        "  border-bottom: 1px solid #3C3C3C;"
        "}"
        "QComboBox {"
        "  background: #2D2D2D;"
        "  color: #D4D4D4;"
        "  border: 1px solid #3C3C3C;"
        "  border-radius: 2px;"
        "  padding: 2px 4px;"
        "}"
        "QComboBox::drop-down {"
        "  border: none;"
        "  width: 18px;"
        "}"
        "QComboBox QAbstractItemView {"
        "  background: #252526;"
        "  color: #D4D4D4;"
        "  selection-background-color: #264F78;"
        "}"
        "QSplitter::handle {"
        "  background: #3C3C3C;"
        "}"
        "QTabBar::tab {"
        "  background: #252526;"
        "  color: #9E9E9E;"
        "  border: 1px solid #3C3C3C;"
        "  border-bottom: none;"
        "  padding: 4px 12px;"
        "}"
        "QTabBar::tab:selected {"
        "  background: #1E1E1E;"
        "  color: #D4D4D4;"
        "}"
        "QTabBar::tab:hover {"
        "  background: #2D2D2D;"
        "}"
        "QStatusBar {"
        "  background: #007ACC;"
        "  color: #FFFFFF;"
        "}"
    );

    qApp->setStyleSheet(qss);

    loadProject();
}

void MainWindow::buildMenu()
{
    QMenuBar* mb = menuBar();

    // File
    QMenu* fileMenu = mb->addMenu(QStringLiteral("&File"));
    fileMenu->addAction(QStringLiteral("Launch..."), this, [this]() {
        QString exe = QFileDialog::getOpenFileName(this, QStringLiteral("Launch Executable"),
                                                   QString(),
                                                   QStringLiteral("Executables (*.exe);;All Files (*)"));
        if (!exe.isEmpty()) runCommand(QStringLiteral("launch ") + exe);
    });
    fileMenu->addAction(QStringLiteral("Attach..."), this, [this]() {
        showAttachDialog();
    });
    fileMenu->addSeparator();
    fileMenu->addAction(QStringLiteral("Exit"), this, &QWidget::close);

    // Debug
    QMenu* dbgMenu = mb->addMenu(QStringLiteral("&Debug"));
    dbgMenu->addAction(QStringLiteral("Go\tF5"),        this, [this]() { runCommand(QStringLiteral("go")); });
    dbgMenu->addAction(QStringLiteral("Pause\tF6"),     this, [this]() { runCommand(QStringLiteral("pause")); });
    dbgMenu->addAction(QStringLiteral("Step In\tF7"),   this, [this]() { runCommand(QStringLiteral("si")); });
    dbgMenu->addAction(QStringLiteral("Step Over\tF8"), this, [this]() { runCommand(QStringLiteral("so")); });
    dbgMenu->addAction(QStringLiteral("Step Out\tF9"),  this, [this]() { runCommand(QStringLiteral("sout")); });
    dbgMenu->addSeparator();
    dbgMenu->addAction(QStringLiteral("Kill"),   this, [this]() { runCommand(QStringLiteral("kill")); });
    dbgMenu->addAction(QStringLiteral("Detach"), this, [this]() { runCommand(QStringLiteral("detach")); });

    // View
    QMenu* viewMenu = mb->addMenu(QStringLiteral("&View"));
    viewMenu->addAction(QStringLiteral("Goto Address...\tCtrl+G"), this, [this]() {
        bool ok = false;
        QString addr = QInputDialog::getText(this, QStringLiteral("Goto Address"),
                                             QStringLiteral("Address or symbol:"),
                                             QLineEdit::Normal, QString(), &ok);
        if (ok && !addr.isEmpty()) refreshDisasm(addr);
    });
    viewMenu->addAction(QStringLiteral("Find...\tCtrl+F"), this, [this]() {
        log(QStringLiteral("Find not yet implemented"), LogKind::Warn);
    });
    viewMenu->addAction(QStringLiteral("Search Memory..."), this, [this]() {
        showSearchDialog();
    });
    viewMenu->addAction(QStringLiteral("Refresh All\tCtrl+R"), this, [this]() { refreshAll(); });

    // Breakpoints
    QMenu* bpMenu = mb->addMenu(QStringLiteral("&Breakpoints"));
    bpMenu->addAction(QStringLiteral("Set at cursor"), this, [this]() {
        int row = disasmTable->currentRow();
        if (row < 0) return;
        auto* it = disasmTable->item(row, 1);
        if (it) toggleBpAt(it->text());
    });
    bpMenu->addAction(QStringLiteral("Clear all"), this, [this]() { runCommand(QStringLiteral("bc all")); });
    bpMenu->addAction(QStringLiteral("List"),      this, [this]() { runCommand(QStringLiteral("bl")); });
}

void MainWindow::buildToolBar()
{
    QToolBar* tb = addToolBar(QStringLiteral("Main"));
    tb->setMovable(false);

    QLabel* beLbl = new QLabel(QStringLiteral("  Backend: "), this);
    beLbl->setStyleSheet(QStringLiteral("color:#9CDCFE;font-weight:bold;"));
    tb->addWidget(beLbl);

    backendCombo = new QComboBox(this);
    backendCombo->addItems({QStringLiteral("titan"),
                            QStringLiteral("winapi"),
                            QStringLiteral("dbgeng"),
                            QStringLiteral("frida"),
                            QStringLiteral("gdbremote"),
                            QStringLiteral("lldb")});
    backendCombo->setCurrentText(QStringLiteral("titan"));
    backendCombo->setFixedWidth(100);
    connect(backendCombo, &QComboBox::currentTextChanged, this, [this](const QString& t) {
        selectedBackendKind = t;
        startDaemon();
    });
    tb->addWidget(backendCombo);
    tb->addSeparator();

    auto mkBtn = [&](const QString& label, const QString& styleExtra = QString()) -> QPushButton* {
        auto* btn = new QPushButton(label, this);
        btn->setFixedHeight(26);
        if (!styleExtra.isEmpty()) btn->setStyleSheet(styleExtra);
        tb->addWidget(btn);
        return btn;
    };

    auto* launchBtn = mkBtn(QStringLiteral("Launch"));
    auto* attachBtn = mkBtn(QStringLiteral("Attach"));
    auto* detachBtn = mkBtn(QStringLiteral("Detach"));
    auto* killBtn   = mkBtn(QStringLiteral("Kill"));
    tb->addSeparator();

    runBtn = mkBtn(QStringLiteral("Run (F5)"));
    pauseBtn = mkBtn(QStringLiteral("Pause (F6)"));
    tb->addSeparator();

    auto* siBtn  = mkBtn(QStringLiteral("SI (F7)"));
    auto* soBtn  = mkBtn(QStringLiteral("SO (F8)"));
    auto* srBtn  = mkBtn(QStringLiteral("SR (F9)"));
    tb->addSeparator();

    auto* procBtn = mkBtn(QStringLiteral("Proc"));

    connect(launchBtn, &QPushButton::clicked, this, [this]() {
        QString exe = QFileDialog::getOpenFileName(this, QStringLiteral("Launch"), QString(),
                                                   QStringLiteral("Executables (*.exe);;All Files (*)"));
        if (!exe.isEmpty()) runCommand(QStringLiteral("launch ") + exe);
    });
    connect(attachBtn, &QPushButton::clicked, this, [this]() {
        showAttachDialog();
    });
    connect(detachBtn, &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("detach")); });
    connect(killBtn,   &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("kill")); });
    connect(runBtn,    &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("go")); });
    connect(pauseBtn,  &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("pause")); });
    connect(siBtn,     &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("si")); });
    connect(soBtn,     &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("so")); });
    connect(srBtn,     &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("sout")); });
    connect(procBtn,   &QPushButton::clicked, this, [this]() { runCommand(QStringLiteral("proc")); });
}

void MainWindow::buildCentralWidget()
{
    QFont mono(QStringLiteral("Consolas"), 11);

    // Disasm table
    disasmTable = makeTable({QStringLiteral(""),
                             QStringLiteral("Address"),
                             QStringLiteral("Bytes"),
                             QStringLiteral("Mnemonic"),
                             QStringLiteral("Operands"),
                             QStringLiteral("Comment")});
    disasmTable->setColumnWidth(0, 18);
    disasmTable->setColumnWidth(1, 155);
    disasmTable->setColumnWidth(2, 210);
    disasmTable->setColumnWidth(3, 84);
    disasmTable->setColumnWidth(4, 400);
    disasmTable->horizontalHeader()->setStretchLastSection(true);
    disasmTable->setContextMenuPolicy(Qt::CustomContextMenu);
    disasmTable->installEventFilter(this);

    // Disasm address bar
    disasmAddrBar = new QLineEdit(this);
    disasmAddrBar->setPlaceholderText(QStringLiteral("Address or symbol (Enter to navigate)"));
    disasmAddrBar->setFont(mono);
    disasmAddrBar->setFixedHeight(24);
    connect(disasmAddrBar, &QLineEdit::returnPressed, this, [this]() {
        refreshDisasm(disasmAddrBar->text());
    });

    QWidget* disasmPanel = new QWidget(this);
    QVBoxLayout* disasmLayout = new QVBoxLayout(disasmPanel);
    disasmLayout->setContentsMargins(0, 0, 0, 0);
    disasmLayout->setSpacing(2);

    QHBoxLayout* addrRow = new QHBoxLayout;
    addrRow->setContentsMargins(0, 0, 0, 0);
    QLabel* addrLbl = new QLabel(QStringLiteral("  Goto:"), this);
    addrLbl->setStyleSheet(QStringLiteral("color:#9CDCFE;font-weight:bold;"));
    addrRow->addWidget(addrLbl);
    addrRow->addWidget(disasmAddrBar, 1);
    auto* gotoBtn = new QPushButton(QStringLiteral("Go"), this);
    gotoBtn->setFixedSize(36, 24);
    connect(gotoBtn, &QPushButton::clicked, this, [this]() {
        refreshDisasm(disasmAddrBar->text());
    });
    addrRow->addWidget(gotoBtn);
    disasmLayout->addLayout(addrRow);
    disasmLayout->addWidget(disasmTable, 1);

    // Register table
    regTable = makeTable({QStringLiteral("Register"),
                          QStringLiteral("Value"),
                          QStringLiteral("Changed")});
    regTable->setFixedWidth(260);
    regTable->horizontalHeader()->setStretchLastSection(true);
    regTable->setColumnWidth(0, 72);
    regTable->setColumnWidth(1, 140);

    // Central splitter
    QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(disasmPanel);
    splitter->addWidget(regTable);
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 0);
    setCentralWidget(splitter);

    // Context menu (feature 7 - enhanced)
    connect(disasmTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        int row = disasmTable->rowAt(pos.y());
        if (row < 0) return;
        auto* addrItem = disasmTable->item(row, 1);
        if (!addrItem) return;
        QString addr = addrItem->text();

        QMenu menu(this);
        bool hasBp = activeBpAddrs.contains(fmtAddr(addr));
        menu.addAction(hasBp ? QStringLiteral("Clear Breakpoint") : QStringLiteral("Set Breakpoint"),
                       this, [this, addr]() { toggleBpAt(addr); });
        
        QMenu* hwBpMenu = menu.addMenu(QStringLiteral("Hardware Breakpoints"));
        hwBpMenu->addAction(QStringLiteral("Toggle Execution HW BP"), this, [this, addr]() { toggleHwBpAt(addr, QStringLiteral("x")); });
        hwBpMenu->addAction(QStringLiteral("Toggle Read/Write HW BP"), this, [this, addr]() { toggleHwBpAt(addr, QStringLiteral("rw")); });
        hwBpMenu->addAction(QStringLiteral("Toggle Write HW BP"), this, [this, addr]() { toggleHwBpAt(addr, QStringLiteral("w")); });


        bool hasBm = bookmarks.contains(addr);
        menu.addAction(hasBm ? QStringLiteral("Remove Bookmark") : QStringLiteral("Add Bookmark"),
                       this, [this, addr, hasBm]() { 
                           if (hasBm) removeBookmark(addr); 
                           else addBookmark(addr); 
                           updateDisasmRowHighlight(disasmTable->currentRow(), disasmTable->item(disasmTable->currentRow(), 1)->text() == rip, activeBpAddrs.contains(fmtAddr(addr)));
                       });
        
        menu.addAction(QStringLiteral("Run to Here"), this, [this, addr]() { runToAddr(addr); });
        menu.addSeparator();
        // Feature 7: Follow in Dump
        menu.addAction(QStringLiteral("Follow in Dump"), this, [this, addr]() {
            memAddrBar->setText(addr);
            refreshMem();
        });
        // Feature 7: Goto RIP
        menu.addAction(QStringLiteral("Goto RIP"), this, [this]() {
            if (!rip.isEmpty()) refreshDisasm(rip);
        });
        menu.addSeparator();
        // Feature 7: Edit (NOP out)
        menu.addAction(QStringLiteral("Edit (NOP out)"), this, [this, addr]() {
            bool ok = false;
            int cnt = QInputDialog::getInt(this, QStringLiteral("NOP Out"),
                                           QStringLiteral("Number of bytes to NOP:"),
                                           1, 1, 32, 1, &ok);
            if (ok) nopOutAt(addr, cnt);
        });
        menu.addAction(QStringLiteral("Search Memory Here"), this, [this]() {
            showSearchDialog();
        });
        // Feature 7: Copy Disasm Text
        menu.addAction(QStringLiteral("Copy Disasm Text"), this, [this, row]() {
            auto* mn = disasmTable->item(row, 3);
            auto* op = disasmTable->item(row, 4);
            QString txt;
            if (mn) txt += mn->text();
            if (op && !op->text().isEmpty()) txt += QLatin1Char(' ') + op->text();
            QApplication::clipboard()->setText(txt);
        });
        menu.addSeparator();
        menu.addAction(QStringLiteral("Copy Address"), this, [addr]() {
            QApplication::clipboard()->setText(addr);
        });
        menu.addAction(QStringLiteral("Copy Row"), this, [this, row]() {
            QStringList parts;
            for (int c = 0; c < disasmTable->columnCount(); ++c) {
                auto* it = disasmTable->item(row, c);
                if (it) parts << it->text();
            }
            QApplication::clipboard()->setText(parts.join(QStringLiteral("  ")));
        });
        menu.exec(disasmTable->mapToGlobal(pos));
    });

    // Double-click
    connect(disasmTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int col) {
        auto* addrItem = disasmTable->item(row, 1);
        if (!addrItem) return;
        if (col == 0)      toggleBpAt(addrItem->text());
        else if (col == 1) refreshDisasm(addrItem->text());
    });

    // Infinite scroll - append disasm when near bottom
    connect(disasmTable->verticalScrollBar(), &QScrollBar::valueChanged, this, [this](int val) {
        QScrollBar* sb = disasmTable->verticalScrollBar();
        if (val >= sb->maximum() - 4 && !disasmFetchingMore) {
            int last = disasmTable->rowCount() - 1;
            if (last >= 0) {
                auto* it = disasmTable->item(last, 1);
                if (it) appendDisasm(it->text());
            }
        }
    });
}

void MainWindow::buildDocks()
{
    setTabPosition(Qt::BottomDockWidgetArea, QTabWidget::North);
    QFont mono(QStringLiteral("Consolas"), 11);

    // Memory dock
    QDockWidget* memDock = makeDock(QStringLiteral("Memory"), Qt::BottomDockWidgetArea);
    QWidget* memWidget = new QWidget;
    QVBoxLayout* memLayout = new QVBoxLayout(memWidget);
    memLayout->setContentsMargins(4, 4, 4, 4);
    memLayout->setSpacing(2);

    QHBoxLayout* memBarRow = new QHBoxLayout;
    memBarRow->setContentsMargins(0, 0, 0, 0);
    QLabel* maLbl = new QLabel(QStringLiteral("Addr:"), memWidget);
    maLbl->setStyleSheet(QStringLiteral("color:#9CDCFE;font-weight:bold;"));
    memAddrBar = new QLineEdit(memWidget);
    memAddrBar->setPlaceholderText(QStringLiteral("Address or symbol"));
    memAddrBar->setFont(mono);
    memAddrBar->setFixedHeight(22);
    QLabel* mlLbl = new QLabel(QStringLiteral("Len:"), memWidget);
    mlLbl->setStyleSheet(QStringLiteral("color:#9CDCFE;font-weight:bold;"));
    memLenBar = new QLineEdit(memWidget);
    memLenBar->setPlaceholderText(QStringLiteral("0x100"));
    memLenBar->setText(QStringLiteral("0x100"));
    memLenBar->setFont(mono);
    memLenBar->setFixedWidth(80);
    memLenBar->setFixedHeight(22);
    auto* readBtn = new QPushButton(QStringLiteral("Read"), memWidget);
    readBtn->setFixedSize(52, 22);
    connect(readBtn,   &QPushButton::clicked,   this, &MainWindow::refreshMem);
    connect(memAddrBar, &QLineEdit::returnPressed, this, &MainWindow::refreshMem);
    connect(memLenBar,  &QLineEdit::returnPressed, this, &MainWindow::refreshMem);
    memBarRow->addWidget(maLbl);
    memBarRow->addWidget(memAddrBar, 1);
    memBarRow->addWidget(mlLbl);
    memBarRow->addWidget(memLenBar);
    memBarRow->addWidget(readBtn);
    QStringList memHeaders;
    memHeaders << QStringLiteral("Address");
    for (int i = 0; i < 16; ++i) {
        memHeaders << QString::number(i, 16).toUpper().rightJustified(2, QLatin1Char('0'));
    }
    memHeaders << QStringLiteral("ASCII");
    memView = makeTable(memHeaders);
    memView->setSelectionBehavior(QAbstractItemView::SelectItems);
    memView->setColumnWidth(0, 145);
    for (int i = 1; i <= 16; ++i) {
        memView->setColumnWidth(i, 32);
    }
    memView->setColumnWidth(17, 180);
    memView->horizontalHeader()->setStretchLastSection(true);
    memView->installEventFilter(this);
    memLayout->addLayout(memBarRow);
    memLayout->addWidget(memView, 1);
    memDock->setWidget(memWidget);

    // Breakpoints dock
    QDockWidget* bpDock = makeDock(QStringLiteral("Breakpoints"), Qt::BottomDockWidgetArea);
    bpTable = makeTable({QStringLiteral("#"),
                         QStringLiteral("Address"),
                         QStringLiteral("Kind"),
                         QStringLiteral("Hits"),
                         QStringLiteral("Enabled")});
    bpTable->horizontalHeader()->setStretchLastSection(true);
    bpDock->setWidget(bpTable);
    tabifyDockWidget(memDock, bpDock);

    // Modules dock
    QDockWidget* modDock = makeDock(QStringLiteral("Modules"), Qt::BottomDockWidgetArea);
    modTable = makeTable({QStringLiteral("Base"),
                          QStringLiteral("Size"),
                          QStringLiteral("Name"),
                          QStringLiteral("Path")});
    modTable->horizontalHeader()->setStretchLastSection(true);
    modTable->setColumnWidth(0, 155);
    modTable->setColumnWidth(1, 80);
    modTable->setColumnWidth(2, 140);
    modDock->setWidget(modTable);
    tabifyDockWidget(bpDock, modDock);

    // Memory Map dock
    QDockWidget* memMapDock = makeDock(QStringLiteral("Memory Map"), Qt::BottomDockWidgetArea);
    memMapTable = makeTable({QStringLiteral("Base Address"),
                             QStringLiteral("Size"),
                             QStringLiteral("Protect"),
                             QStringLiteral("State"),
                             QStringLiteral("Type"),
                             QStringLiteral("Module")});
    memMapTable->horizontalHeader()->setStretchLastSection(true);
    memMapTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(memMapTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        int row = memMapTable->rowAt(pos.y());
        if (row < 0) return;
        auto* baseItem = memMapTable->item(row, 0);
        if (!baseItem) return;
        QString baseAddr = baseItem->text();

        QMenu menu(this);
        menu.addAction(QStringLiteral("Follow in Dump"), this, [this, baseAddr]() {
            memAddrBar->setText(baseAddr);
            refreshMem();
        });
        menu.exec(memMapTable->mapToGlobal(pos));
    });
    memMapDock->setWidget(memMapTable);
    tabifyDockWidget(modDock, memMapDock);

    // Threads dock
    QDockWidget* thrDock = makeDock(QStringLiteral("Threads"), Qt::BottomDockWidgetArea);
    thrTable = makeTable({QStringLiteral("TID"),
                          QStringLiteral("State"),
                          QStringLiteral("Start Address"),
                          QStringLiteral("Name")});
    thrTable->horizontalHeader()->setStretchLastSection(true);
    thrDock->setWidget(thrTable);
    tabifyDockWidget(memMapDock, thrDock);

    // Call Stack dock
    QDockWidget* stackDock = makeDock(QStringLiteral("Call Stack"), Qt::BottomDockWidgetArea);
    stackTable = makeTable({QStringLiteral("Frame"),
                            QStringLiteral("Address"),
                            QStringLiteral("Symbol"),
                            QStringLiteral("Module"),
                            QStringLiteral("Source")});
    stackTable->horizontalHeader()->setStretchLastSection(true);
    stackTable->setColumnWidth(0, 50);
    stackTable->setColumnWidth(1, 155);
    stackTable->setColumnWidth(2, 240);
    stackTable->setColumnWidth(3, 140);
    stackDock->setWidget(stackTable);
    tabifyDockWidget(thrDock, stackDock);

    // Watchpoints dock
    QDockWidget* wpDock = makeDock(QStringLiteral("Watchpoints"), Qt::BottomDockWidgetArea);
    wpTable = makeTable({QStringLiteral("#"),
                         QStringLiteral("Address"),
                         QStringLiteral("Size"),
                         QStringLiteral("Kind"),
                         QStringLiteral("Enabled")});
    wpTable->horizontalHeader()->setStretchLastSection(true);
    wpDock->setWidget(wpTable);
    tabifyDockWidget(stackDock, wpDock);

    // Log / Console dock
    QDockWidget* logDock = makeDock(QStringLiteral("Log / Console"), Qt::BottomDockWidgetArea);
    QWidget* logWidget = new QWidget;
    QVBoxLayout* logLayout = new QVBoxLayout(logWidget);
    logLayout->setContentsMargins(4, 4, 4, 4);
    logLayout->setSpacing(2);

    logView = new QTextEdit(logWidget);
    logView->setReadOnly(true);
    logView->setFont(mono);
    logView->setLineWrapMode(QTextEdit::NoWrap);

    QHBoxLayout* cmdRow = new QHBoxLayout;
    cmdRow->setContentsMargins(0, 0, 0, 0);
    QLabel* promptLbl = new QLabel(QStringLiteral("hyw>"), logWidget);
    promptLbl->setStyleSheet(
        QStringLiteral("color:#58A8F8;font-weight:bold;font-family:Consolas;font-size:11pt;"));
    cmdBar = new QLineEdit(logWidget);
    cmdBar->setFont(mono);
    cmdBar->setFixedHeight(22);
    cmdBar->setPlaceholderText(QStringLiteral("Enter command (type 'help' for list)"));
    // Install event filter for command history (feature 1)
    cmdBar->installEventFilter(this);

    // Command autocomplete (feature 9)
    QStringList completions = {
        QStringLiteral("go"), QStringLiteral("pause"), QStringLiteral("si"),
        QStringLiteral("so"), QStringLiteral("sout"), QStringLiteral("bp"),
        QStringLiteral("bc"), QStringLiteral("bl"), QStringLiteral("mem"),
        QStringLiteral("regs"), QStringLiteral("setreg"), QStringLiteral("threads"),
        QStringLiteral("modules"), QStringLiteral("stack"), QStringLiteral("proc"),
        QStringLiteral("disasm"), QStringLiteral("wp"), QStringLiteral("wc"),
        QStringLiteral("wl"), QStringLiteral("refresh"), QStringLiteral("launch"),
        QStringLiteral("attach"), QStringLiteral("detach"), QStringLiteral("kill"),
        QStringLiteral("help"), QStringLiteral("raw")
    };
    auto* completer = new QCompleter(completions, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    completer->setCompletionMode(QCompleter::PopupCompletion);
    cmdBar->setCompleter(completer);

    connect(cmdBar, &QLineEdit::returnPressed, this, [this]() {
        QString line = cmdBar->text().trimmed();
        if (!line.isEmpty()) {
            // Feature 1: add to history
            if (cmdHistory.isEmpty() || cmdHistory.last() != line)
                cmdHistory.append(line);
            cmdHistoryIdx = cmdHistory.size(); // reset index (past-end)
            cmdBar->clear();
            runCommand(line);
        }
    });
    cmdRow->addWidget(promptLbl);
    cmdRow->addWidget(cmdBar, 1);

    logLayout->addWidget(logView, 1);
    logLayout->addLayout(cmdRow);
    logDock->setWidget(logWidget);
    tabifyDockWidget(wpDock, logDock);
    
    // Patches dock
    QDockWidget* patchDock = makeDock(QStringLiteral("Patches"), Qt::BottomDockWidgetArea);
    patchTable = makeTable({QStringLiteral("Address"),
                            QStringLiteral("Old"),
                            QStringLiteral("New"),
                            QStringLiteral("State")});
    patchTable->horizontalHeader()->setStretchLastSection(true);
    patchTable->setColumnWidth(0, 140);
    patchTable->setColumnWidth(1, 100);
    patchTable->setColumnWidth(2, 100);
    patchTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(patchTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        int row = patchTable->rowAt(pos.y());
        if (row < 0) return;
        auto* addrItem = patchTable->item(row, 0);
        if (!addrItem) return;
        QString addr = addrItem->text();

        QMenu menu(this);
        menu.addAction(QStringLiteral("Revert Patch"), this, [this, addr]() {
            revertPatch(addr);
        });
        menu.exec(patchTable->mapToGlobal(pos));
    });
    patchDock->setWidget(patchTable);
    tabifyDockWidget(logDock, patchDock);

    logDock->raise();

    // Stack Memory dock (feature 8) - right dock area
    QDockWidget* stackMemDock = makeDock(QStringLiteral("Stack"), Qt::RightDockWidgetArea);
    stackMemTable = makeTable({QStringLiteral("Address"),
                               QStringLiteral("Value (hex)"),
                               QStringLiteral("Value (ASCII)")});
    stackMemTable->setColumnWidth(0, 145);
    stackMemTable->setColumnWidth(1, 145);
    stackMemTable->horizontalHeader()->setStretchLastSection(true);
    stackMemDock->setWidget(stackMemTable);

    // Bookmarks dock
    QDockWidget* bmDock = makeDock(QStringLiteral("Bookmarks"), Qt::BottomDockWidgetArea);
    bookmarkTable = makeTable({QStringLiteral("Address"),
                               QStringLiteral("Label"),
                               QStringLiteral("Comment")});
    bookmarkTable->horizontalHeader()->setStretchLastSection(true);
    bookmarkTable->setColumnWidth(0, 155);
    bookmarkTable->setColumnWidth(1, 140);
    bmDock->setWidget(bookmarkTable);
    tabifyDockWidget(logDock, bmDock);

    // Search Results dock
    QDockWidget* searchDock = makeDock(QStringLiteral("Search Results"), Qt::BottomDockWidgetArea);
    searchTable = makeTable({QStringLiteral("Address"),
                             QStringLiteral("Disassembly"),
                             QStringLiteral("String")});
    searchTable->setColumnWidth(0, 155);
    searchTable->setColumnWidth(1, 400);
    searchTable->horizontalHeader()->setStretchLastSection(true);
    searchDock->setWidget(searchTable);
    tabifyDockWidget(logDock, searchDock);

    connect(searchTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int col) {
        auto* addrItem = searchTable->item(row, 0);
        if (addrItem) refreshDisasm(addrItem->text());
    });

    resizeDocks({logDock}, {280}, Qt::Vertical);
    resizeDocks({stackMemDock}, {220}, Qt::Horizontal);
}

QTableWidget* MainWindow::makeTable(const QStringList& headers)
{
    QFont mono(QStringLiteral("Consolas"), 11);
    auto* t = new QTableWidget(0, headers.size(), this);
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->hide();
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setShowGrid(false);
    t->setFont(mono);
    t->horizontalHeader()->setHighlightSections(false);
    t->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    return t;
}

QDockWidget* MainWindow::makeDock(const QString& title, Qt::DockWidgetArea area)
{
    auto* dock = new QDockWidget(title, this);
    dock->setAllowedAreas(Qt::AllDockWidgetAreas);
    addDockWidget(area, dock);
    return dock;
}

QTableWidgetItem* MainWindow::tableItem(const QString& text, const QColor& fg, bool bold)
{
    auto* item = new QTableWidgetItem(text);
    item->setForeground(fg);
    if (bold) {
        QFont f = item->font();
        f.setBold(true);
        item->setFont(f);
    }
    return item;
}

void MainWindow::setStatus(const QString& msg)
{
    if (statusLabel)
        statusLabel->setText(QStringLiteral(" ") + msg);
}

bool MainWindow::eventFilter(QObject* obj, QEvent* ev)
{
    // F2/F5/F7/F8/F9 in disasm table
    if (obj == disasmTable && ev->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->text() == QStringLiteral(";")) {
            int row = disasmTable->currentRow();
            if (row >= 0) {
                auto* it = disasmTable->item(row, 1);
                if (it) editComment(it->text());
            }
            return true;
        }
        if (ke->text() == QStringLiteral(":")) {
            int row = disasmTable->currentRow();
            if (row >= 0) {
                auto* it = disasmTable->item(row, 1);
                if (it) editLabel(it->text());
            }
            return true;
        }
        switch (ke->key()) {
            case Qt::Key_F2: {
                int row = disasmTable->currentRow();
                if (row >= 0) {
                    auto* it = disasmTable->item(row, 1);
                    if (it) toggleBpAt(it->text());
                }
                return true;
            }
            case Qt::Key_F5: runCommand(QStringLiteral("go"));   return true;
            case Qt::Key_F7: runCommand(QStringLiteral("si"));   return true;
            case Qt::Key_F8: runCommand(QStringLiteral("so"));   return true;
            case Qt::Key_F9: runCommand(QStringLiteral("sout")); return true;
            default: break;
        }
    }

    // Hex Editor edit event
    if (obj == memView && ev->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        int row = memView->currentRow();
        int col = memView->currentColumn();
        if (row >= 0 && col >= 1 && col <= 16) {
            QString txt = ke->text().trimmed();
            bool isHex = false;
            if (txt.length() == 1) {
                txt.toInt(&isHex, 16);
            }
            if (isHex || ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
                auto* it = memView->item(row, col);
                QString curVal = it ? it->text().trimmed() : QStringLiteral("00");
                bool ok = false;
                QString newVal = QInputDialog::getText(this, QStringLiteral("Edit Byte"),
                                                       QStringLiteral("New hex value:"),
                                                       QLineEdit::Normal, curVal, &ok);
                if (ok && !newVal.isEmpty()) {
                    editMemByte(row, col, newVal);
                }
                return true;
            }
        }
    }

    // Feature 1: command history navigation in cmdBar
    if (obj == cmdBar && ev->type() == QEvent::KeyPress) {
        auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->key() == Qt::Key_Up) {
            if (!cmdHistory.isEmpty()) {
                if (cmdHistoryIdx < 0) cmdHistoryIdx = cmdHistory.size();
                if (cmdHistoryIdx > 0) {
                    --cmdHistoryIdx;
                    cmdBar->setText(cmdHistory[cmdHistoryIdx]);
                    cmdBar->end(false);
                }
            }
            return true;
        }
        if (ke->key() == Qt::Key_Down) {
            if (!cmdHistory.isEmpty() && cmdHistoryIdx >= 0) {
                ++cmdHistoryIdx;
                if (cmdHistoryIdx < cmdHistory.size()) {
                    cmdBar->setText(cmdHistory[cmdHistoryIdx]);
                    cmdBar->end(false);
                } else {
                    cmdHistoryIdx = cmdHistory.size();
                    cmdBar->clear();
                }
            }
            return true;
        }
        if (ke->key() == Qt::Key_Escape) {
            cmdBar->clear();
            cmdHistoryIdx = cmdHistory.size();
            return true;
        }
    }

    return QMainWindow::eventFilter(obj, ev);
}

void MainWindow::setDebugState(const QString& state, const QString& details)
{
    if (!statusLabel || !runBtn || !pauseBtn) return;
    
    QString normalBtn = QStringLiteral("background: transparent; color: #D4D4D4; border: 1px solid #333333; border-radius: 3px; padding: 3px 8px;");
    QString runBtnGreen = QStringLiteral("background: #1E7A3A; color: #FFFFFF; border: 1px solid #2EA04F; border-radius: 3px; padding: 3px 8px;");
    QString pauseBtnYellow = QStringLiteral("background: #7A6A1E; color: #FFFFFF; border: 1px solid #A09020; border-radius: 3px; padding: 3px 8px;");

    if (state == QStringLiteral("exit") || state == QStringLiteral("crash")) {
        statusBar()->setStyleSheet(QStringLiteral("background: #E84040; color: #FFFFFF; font-weight: bold;"));
        statusLabel->setStyleSheet(QStringLiteral("background: transparent; color: #FFFFFF; padding: 2px;"));
        if (!details.isEmpty()) {
            statusLabel->setText(QStringLiteral(" Process Exit (code: ") + details + QStringLiteral(") "));
        } else {
            statusLabel->setText(QStringLiteral(" Process Exit "));
        }
        runBtn->setStyleSheet(normalBtn);
        pauseBtn->setStyleSheet(normalBtn);
        if (disasmTable) disasmTable->setRowCount(0);
        if (regTable) regTable->setRowCount(0);
        if (stackTable) stackTable->setRowCount(0);
        if (modTable) modTable->setRowCount(0);
        if (thrTable) thrTable->setRowCount(0);
        if (memMapTable) memMapTable->setRowCount(0);
    } else if (state == QStringLiteral("pause")) {
        statusBar()->setStyleSheet(QStringLiteral("background: #E8C040; color: #000000; font-weight: bold;"));
        statusLabel->setStyleSheet(QStringLiteral("background: transparent; color: #000000; padding: 2px;"));
        if (!details.isEmpty()) {
            statusLabel->setText(QStringLiteral(" Breakpoint Reached at ") + details + QStringLiteral(" "));
        } else {
            statusLabel->setText(QStringLiteral(" 已暂停 "));
        }
        runBtn->setStyleSheet(normalBtn);
        pauseBtn->setStyleSheet(pauseBtnYellow);
    } else if (state == QStringLiteral("starting")) {
        statusBar()->setStyleSheet(QStringLiteral("background: #000000; color: #40C870; font-weight: bold;"));
        statusLabel->setStyleSheet(QStringLiteral("background: transparent; color: #40C870; padding: 2px;"));
        statusLabel->setText(QStringLiteral(" 启动中... "));
        runBtn->setStyleSheet(normalBtn);
        pauseBtn->setStyleSheet(normalBtn);
    } else if (state == QStringLiteral("running")) {
        statusBar()->setStyleSheet(QStringLiteral("background: #000000; color: #FFFFFF; font-weight: bold;"));
        statusLabel->setStyleSheet(QStringLiteral("background: transparent; color: #FFFFFF; padding: 2px;"));
        statusLabel->setText(QStringLiteral(" 正在运行... "));
        runBtn->setStyleSheet(runBtnGreen);
        pauseBtn->setStyleSheet(normalBtn);
    }
    
    QCoreApplication::processEvents();
}


