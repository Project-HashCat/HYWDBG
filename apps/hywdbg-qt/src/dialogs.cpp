#include "mainwindow.h"

void MainWindow::showAttachDialog()
{
    // Try to get process list from daemon first
    QJsonArray procs;
    try {
        procs = rpc(QStringLiteral("dbg.processList"), {}).toArray();
    } catch (...) {
        // If RPC fails, fall back to manual PID entry only
    }

    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Attach to Process"));
    dlg.resize(600, 400);

    QVBoxLayout* layout = new QVBoxLayout(&dlg);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    // Process list table
    QFont mono(QStringLiteral("Consolas"), 11);
    auto* procTable = new QTableWidget(0, 4, &dlg);
    procTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("Name"),
        QStringLiteral("Arch"),
        QStringLiteral("Description")
    });
    procTable->verticalHeader()->hide();
    procTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    procTable->setSelectionMode(QAbstractItemView::SingleSelection);
    procTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    procTable->setShowGrid(false);
    procTable->setFont(mono);
    procTable->horizontalHeader()->setHighlightSections(false);
    procTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    procTable->horizontalHeader()->setStretchLastSection(true);
    procTable->setColumnWidth(0, 70);
    procTable->setColumnWidth(1, 160);
    procTable->setColumnWidth(2, 60);

    // Populate table
    for (const QJsonValue& v : procs) {
        QJsonObject pr = v.toObject();
        int row = procTable->rowCount();
        procTable->insertRow(row);
        procTable->setRowHeight(row, 20);
        QString pidStr  = pr[QStringLiteral("pid")].toVariant().toString();
        QString nameStr = pr[QStringLiteral("name")].toVariant().toString();
        QString archStr = pr[QStringLiteral("arch")].toVariant().toString();
        QString descStr = pr[QStringLiteral("path")].toVariant().toString();
        if (descStr.isEmpty())
            descStr = pr[QStringLiteral("description")].toVariant().toString();
        auto mkIt = [](const QString& t, const QColor& c) {
            auto* it = new QTableWidgetItem(t);
            it->setForeground(c);
            return it;
        };
        procTable->setItem(row, 0, mkIt(pidStr,  QColor(0x9C, 0xDC, 0xFE)));
        procTable->setItem(row, 1, mkIt(nameStr, QColor(0xD4, 0xD4, 0xD4)));
        procTable->setItem(row, 2, mkIt(archStr, QColor(0xB5, 0xCE, 0xA8)));
        procTable->setItem(row, 3, mkIt(descStr, QColor(0x70, 0x80, 0x70)));
    }

    layout->addWidget(procTable, 1);

    // Manual PID input row
    QHBoxLayout* manualRow = new QHBoxLayout;
    manualRow->setContentsMargins(0, 0, 0, 0);
    QLabel* pidLblW = new QLabel(QStringLiteral("  Manual PID:"), &dlg);
    pidLblW->setStyleSheet(QStringLiteral("color:#9CDCFE;font-weight:bold;"));
    auto* pidEdit = new QLineEdit(&dlg);
    pidEdit->setFont(mono);
    pidEdit->setFixedHeight(22);
    pidEdit->setPlaceholderText(QStringLiteral("Enter PID manually"));
    manualRow->addWidget(pidLblW);
    manualRow->addWidget(pidEdit, 1);
    layout->addLayout(manualRow);

    // Buttons
    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    layout->addWidget(buttonBox);

    // Double-click on a row: select and accept
    QObject::connect(procTable, &QTableWidget::cellDoubleClicked, [&](int, int) {
        dlg.accept();
    });

    // When a row is selected, fill the manual PID field
    QObject::connect(procTable, &QTableWidget::itemSelectionChanged, [&]() {
        auto items = procTable->selectedItems();
        if (!items.isEmpty()) {
            pidEdit->setText(procTable->item(items.first()->row(), 0)->text());
        }
    });

    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) return;

    // Determine PID: prefer manual field if non-empty, else selected row
    QString pidStr = pidEdit->text().trimmed();
    if (pidStr.isEmpty()) {
        int row = procTable->currentRow();
        if (row >= 0) {
            auto* it = procTable->item(row, 0);
            if (it) pidStr = it->text();
        }
    }

    if (pidStr.isEmpty()) {
        log(QStringLiteral("Attach cancelled: no PID selected"), LogKind::Warn);
        return;
    }

    bool ok = false;
    quint64 pid = pidStr.toULongLong(&ok);
    if (!ok || pid == 0) {
        log(QStringLiteral("Attach: invalid PID: ") + pidStr, LogKind::Error);
        return;
    }

    try {
        setDebugState(QStringLiteral("starting"));
        startDaemon();
        QJsonObject p;
        p[QStringLiteral("pid")] = static_cast<qint64>(pid);
        rpc(QStringLiteral("dbg.attach"), p);
        log(QStringLiteral("Attached to PID ") + QString::number(pid), LogKind::Ok);
        setStatus(QStringLiteral("Attached: PID ") + QString::number(pid));
        // Feature 4: update pidLabel
        if (pidLabel)
            pidLabel->setText(QStringLiteral("PID: ") + QString::number(pid));
        setDebugState(QStringLiteral("pause"));
        QTimer::singleShot(200, this, &MainWindow::refreshAll);
    } catch (const std::exception& e) {
        log(QStringLiteral("Attach failed: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}


void MainWindow::showSearchDialog()
{
    bool ok = false;
    QString pattern = QInputDialog::getText(this, QStringLiteral("Search Memory"),
                                         QStringLiteral("Enter Hex or String pattern:"),
                                         QLineEdit::Normal, QString(), &ok);
    if (!ok || pattern.isEmpty()) return;

    try {
        QJsonObject params;
        params[QStringLiteral("pattern")] = pattern;
        params[QStringLiteral("start")] = rip.isEmpty() ? QStringLiteral("0") : rip;
        params[QStringLiteral("end")] = QStringLiteral("0xFFFFFFFFFFFFFFFF");
        QJsonArray res = rpc(QStringLiteral("dbg.searchMem"), params).toArray();

        searchTable->setRowCount(0);
        for (const QJsonValue& v : res) {
            QString addr = v.toString();
            int row = searchTable->rowCount();
            searchTable->insertRow(row);
            searchTable->setRowHeight(row, 20);

            // Fetch a quick disasm for context
            QString disasmStr;
            QString strStr;
            try {
                QJsonObject dp;
                dp[QStringLiteral("addr")] = addr;
                dp[QStringLiteral("count")] = 1;
                QJsonArray dRes = rpc(QStringLiteral("dbg.disasm"), dp).toArray();
                if (!dRes.isEmpty()) {
                    QJsonObject ins = dRes[0].toObject();
                    QString mn = ins[QStringLiteral("mnemonic")].toString();
                    QString op = ins[QStringLiteral("operands")].toString();
                    disasmStr = mn;
                    if (!op.isEmpty()) disasmStr += QLatin1Char(' ') + op;
                }
                
                // Read a few bytes to show as string
                QJsonObject rp;
                rp[QStringLiteral("addr")] = addr;
                rp[QStringLiteral("len")] = 16;
                QString hexData = rpc(QStringLiteral("dbg.readMem"), rp).toString();
                QByteArray bytes = QByteArray::fromHex(hexData.toLatin1());
                for (char c : bytes) {
                    if (c >= 32 && c <= 126) strStr += c;
                    else strStr += QLatin1Char('.');
                }
            } catch (...) {}

            searchTable->setItem(row, 0, tableItem(addr, QColor(0x9C, 0xDC, 0xFE)));
            searchTable->setItem(row, 1, tableItem(disasmStr, QColor(0xD4, 0xD4, 0xD4)));
            searchTable->setItem(row, 2, tableItem(strStr, QColor(0xCE, 0x91, 0x78)));
        }
        
        if (res.isEmpty()) {
            log(QStringLiteral("Search: No results found for pattern: ") + pattern, LogKind::Warn);
        } else {
            log(QStringLiteral("Search: Found ") + QString::number(res.size()) + QStringLiteral(" matches."), LogKind::Info);
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("Search failed: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}
