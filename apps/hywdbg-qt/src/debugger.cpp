#include "mainwindow.h"

void MainWindow::log(const QString& msg, LogKind kind)
{
    if (!logView) return;
    QString color;
    switch (kind) {
        case LogKind::Ok:    color = QStringLiteral("#40C870"); break;
        case LogKind::Warn:  color = QStringLiteral("#E8C040"); break;
        case LogKind::Error: color = QStringLiteral("#E84040"); break;
        case LogKind::Cmd:   color = QStringLiteral("#58A8F8"); break;
        case LogKind::Event: color = QStringLiteral("#C080F8"); break;
        default:             color = QStringLiteral("#8090A0"); break;
    }
    QString ts   = QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
    QString html = QStringLiteral("<span style=\"color:#505060;\">[%1]</span> "
                                  "<span style=\"color:%2;\">%3</span>")
                   .arg(ts, color, msg.toHtmlEscaped());
    logView->append(html);
    QScrollBar* sb = logView->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void MainWindow::refreshModules()
{
    try {
        QJsonArray mods = rpc(QStringLiteral("dbg.modules"), {}).toArray();
        modTable->setRowCount(0);
        for (const QJsonValue& v : mods) {
            QJsonObject m = v.toObject();
            int row = modTable->rowCount();
            modTable->insertRow(row);
            modTable->setRowHeight(row, 20);
            modTable->setItem(row, 0, tableItem(fmtAddr(m[QStringLiteral("base")].toVariant().toString()),
                                                 QColor(0x9B, 0xB8, 0xD8)));
            modTable->setItem(row, 1, tableItem(m[QStringLiteral("size")].toVariant().toString(),
                                                 QColor(0x8E, 0x80, 0x60)));
            modTable->setItem(row, 2, tableItem(m[QStringLiteral("name")].toVariant().toString(),
                                                 QColor(0xD4, 0xD4, 0xD4)));
            modTable->setItem(row, 3, tableItem(m[QStringLiteral("path")].toVariant().toString(),
                                                 QColor(0x70, 0x80, 0x70)));
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshModules: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshThreads()
{
    try {
        QJsonArray threads = rpc(QStringLiteral("dbg.threads"), {}).toArray();
        thrTable->setRowCount(0);
        for (const QJsonValue& v : threads) {
            QJsonObject t = v.toObject();
            int row = thrTable->rowCount();
            thrTable->insertRow(row);
            thrTable->setRowHeight(row, 20);
            thrTable->setItem(row, 0, tableItem(t[QStringLiteral("id")].toVariant().toString(),
                                                 QColor(0x9C, 0xDC, 0xFE)));
            bool active = t[QStringLiteral("active")].toBool(true);
            thrTable->setItem(row, 1, tableItem(active ? QStringLiteral("Active") : QStringLiteral("Suspended"),
                                                 QColor(0xB5, 0xCE, 0xA8)));
            thrTable->setItem(row, 2, tableItem(fmtAddr(t[QStringLiteral("pc")].toVariant().toString()),
                                                 QColor(0x9B, 0xB8, 0xD8)));
            thrTable->setItem(row, 3, tableItem(t[QStringLiteral("name")].toVariant().toString(),
                                                 QColor(0xD4, 0xD4, 0xD4)));
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshThreads: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshCallStack()
{
    try {
        QJsonArray frames = rpc(QStringLiteral("dbg.callstack"), {}).toArray();
        stackTable->setRowCount(0);
        for (int i = 0; i < frames.size(); ++i) {
            QJsonObject f = frames[i].toObject();
            int row = stackTable->rowCount();
            stackTable->insertRow(row);
            stackTable->setRowHeight(row, 20);
            stackTable->setItem(row, 0, tableItem(QString::number(i),
                                                   QColor(0x80, 0x80, 0x80)));
            stackTable->setItem(row, 1, tableItem(fmtAddr(f[QStringLiteral("addr")].toVariant().toString()),
                                                   QColor(0x9B, 0xB8, 0xD8)));
            stackTable->setItem(row, 2, tableItem(f[QStringLiteral("symbol")].toVariant().toString(),
                                                   QColor(0xD4, 0xD4, 0xD4)));
            stackTable->setItem(row, 3, tableItem(f[QStringLiteral("module")].toVariant().toString(),
                                                   QColor(0x9C, 0xDC, 0xFE)));
            stackTable->setItem(row, 4, tableItem(f[QStringLiteral("source")].toVariant().toString(),
                                                   QColor(0x70, 0x80, 0x70)));
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshCallStack: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshBpList()
{
    try {
        QJsonArray bps = rpc(QStringLiteral("dbg.bpList"), {}).toArray();
        activeBpAddrs.clear();
        bpTable->setRowCount(0);
        for (int i = 0; i < bps.size(); ++i) {
            QJsonObject bp  = bps[i].toObject();
            QString fmted   = fmtAddr(bp[QStringLiteral("addr")].toVariant().toString());
            activeBpAddrs.insert(fmted);
            int row = bpTable->rowCount();
            bpTable->insertRow(row);
            bpTable->setRowHeight(row, 20);
            bpTable->setItem(row, 0, tableItem(QString::number(i + 1), QColor(0x80, 0x80, 0x80)));
            bpTable->setItem(row, 1, tableItem(fmted,                  QColor(0xFF, 0x88, 0x66)));

            QString kindStr = bp[QStringLiteral("kind")].toVariant().toString();
            if (kindStr.isEmpty()) kindStr = QStringLiteral("int3");
            bpTable->setItem(row, 2, tableItem(kindStr, QColor(0xC8, 0xA0, 0x60)));

            QString hitsStr = bp[QStringLiteral("hit_count")].toVariant().toString();
            if (hitsStr.isEmpty()) hitsStr = QStringLiteral("0");
            bpTable->setItem(row, 3, tableItem(hitsStr, QColor(0x9C, 0xDC, 0xFE)));

            bool en = bp[QStringLiteral("enabled")].toBool(true);
            bpTable->setItem(row, 4, tableItem(en ? QStringLiteral("Yes") : QStringLiteral("No"),
                                               en ? QColor(0x40, 0xC8, 0x70) : QColor(0xE8, 0x40, 0x40)));
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshBpList: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshMemoryMap()
{
    try {
        QJsonArray regions = rpc(QStringLiteral("dbg.memoryMap"), {}).toArray();
        memMapTable->setRowCount(0);
        for (const QJsonValue& v : regions) {
            QJsonObject r = v.toObject();
            int row = memMapTable->rowCount();
            memMapTable->insertRow(row);
            memMapTable->setRowHeight(row, 20);
            memMapTable->setItem(row, 0, tableItem(fmtAddr(r[QStringLiteral("base")].toVariant().toString()),
                                                    QColor(0x9B, 0xB8, 0xD8)));
            memMapTable->setItem(row, 1, tableItem(r[QStringLiteral("size")].toVariant().toString(),
                                                    QColor(0x8E, 0x80, 0x60)));
            memMapTable->setItem(row, 2, tableItem(r[QStringLiteral("protect")].toVariant().toString(),
                                                    QColor(0xD4, 0xD4, 0xD4)));
            memMapTable->setItem(row, 3, tableItem(r[QStringLiteral("state")].toVariant().toString(),
                                                    QColor(0xD4, 0xD4, 0xD4)));
            memMapTable->setItem(row, 4, tableItem(r[QStringLiteral("type")].toVariant().toString(),
                                                    QColor(0xD4, 0xD4, 0xD4)));
            memMapTable->setItem(row, 5, tableItem(r[QStringLiteral("name")].toVariant().toString(),
                                                    QColor(0x70, 0x80, 0x70)));
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshMemoryMap: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshAll()
{
    refreshRegs();
    if (!rip.isEmpty()) refreshDisasm(rip);
    refreshModules();
    refreshMemoryMap();
    refreshThreads();
    refreshCallStack();
    refreshBpList();
    refreshStack();
}

void MainWindow::toggleBpAt(const QString& rawAddr)
{
    try {
        QString resolved = resolveToAddr(rawAddr);
        if (resolved.isEmpty()) resolved = fmtAddr(rawAddr);

        if (activeBpAddrs.contains(resolved)) {
            QJsonObject p;
            p[QStringLiteral("addr")] = resolved;
            rpc(QStringLiteral("dbg.bpClear"), p);
            activeBpAddrs.remove(resolved);
            log(QStringLiteral("BP cleared at ") + resolved, LogKind::Warn);
        } else {
            QJsonObject p;
            p[QStringLiteral("addr")] = resolved;
            rpc(QStringLiteral("dbg.bpSet"), p);
            activeBpAddrs.insert(resolved);
            log(QStringLiteral("BP set at ") + resolved, LogKind::Ok);
        }

        bool nowHasBp  = activeBpAddrs.contains(resolved);
        quint64 target = parseAddr(resolved);
        for (int r = 0; r < disasmTable->rowCount(); ++r) {
            auto* it = disasmTable->item(r, 1);
            if (it && parseAddr(it->text()) == target) {
                updateDisasmRowHighlight(r, parseAddr(rip) == target, nowHasBp);
                break;
            }
        }
        refreshBpList();
    } catch (const std::exception& e) {
        log(QStringLiteral("toggleBpAt: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::toggleHwBpAt(const QString& rawAddr, const QString& kind)
{
    try {
        QString resolved = resolveToAddr(rawAddr);
        if (resolved.isEmpty()) resolved = fmtAddr(rawAddr);

        QJsonObject p;
        p[QStringLiteral("addr")] = resolved;
        p[QStringLiteral("kind")] = kind;
        rpc(QStringLiteral("dbg.hwBpSet"), p);
        
        log(QStringLiteral("HW BP (") + kind + QStringLiteral(") toggled/set at ") + resolved, LogKind::Ok);
        refreshBpList();
        if (!rip.isEmpty()) refreshDisasm(rip);
    } catch (const std::exception& e) {
        log(QStringLiteral("toggleHwBpAt: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::runToAddr(const QString& addr)
{
    try {
        QString resolved = resolveToAddr(addr);
        if (resolved.isEmpty()) resolved = fmtAddr(addr);
        QJsonObject bp;
        bp[QStringLiteral("addr")] = resolved;
        bp[QStringLiteral("temp")] = true;
        rpc(QStringLiteral("dbg.bpSet"), bp);
        QJsonObject res = rpc(QStringLiteral("dbg.go"), {}).toObject();
        formatEventDetail(res);
        refreshAll();
    } catch (const std::exception& e) {
        log(QStringLiteral("runToAddr: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::formatEventDetail(const QJsonObject& res)
{
    QString ev = res[QStringLiteral("event")].toVariant().toString();

    if (ev == QStringLiteral("load_dll")) {
        log(QStringLiteral("load_dll  base=") + fmtAddr(res[QStringLiteral("base")].toVariant().toString())
            + QStringLiteral("  ") + res[QStringLiteral("name")].toVariant().toString()
            + QStringLiteral("  ") + res[QStringLiteral("path")].toVariant().toString(),
            LogKind::Event);
    } else if (ev == QStringLiteral("breakpoint")) {
        QString addr = res.contains(QStringLiteral("pc")) ? res[QStringLiteral("pc")].toVariant().toString() : res[QStringLiteral("address")].toVariant().toString();
        log(QStringLiteral("Breakpoint reached at ") + fmtAddr(addr), LogKind::Ok);
    } else if (ev == QStringLiteral("single_step")) {
        QString addr = res.contains(QStringLiteral("pc")) ? res[QStringLiteral("pc")].toVariant().toString() : res[QStringLiteral("address")].toVariant().toString();
        log(QStringLiteral("Single step at ") + fmtAddr(addr), LogKind::Ok);
    } else if (ev == QStringLiteral("exception")) {
        bool fc = res[QStringLiteral("first_chance")].toBool(true);
        QString desc = res[QStringLiteral("description")].toVariant().toString();
        QString addr = res.contains(QStringLiteral("pc")) ? res[QStringLiteral("pc")].toVariant().toString() : res[QStringLiteral("address")].toVariant().toString();
        log(QStringLiteral("EXCEPTION  code=") + res[QStringLiteral("code")].toVariant().toString()
            + QStringLiteral("  addr=") + fmtAddr(addr)
            + (fc ? QStringLiteral("  first-chance") : QStringLiteral("  second-chance"))
            + (desc.isEmpty() ? QString() : QStringLiteral("  (") + desc + QStringLiteral(")")),
            LogKind::Error);
        setDebugState(QStringLiteral("crash"));
    } else if (ev == QStringLiteral("create_thread")) {
        log(QStringLiteral("create_thread  tid=") + res[QStringLiteral("tid")].toVariant().toString()
            + QStringLiteral("  start=") + fmtAddr(res[QStringLiteral("startAddr")].toVariant().toString()),
            LogKind::Event);
    } else if (ev == QStringLiteral("exit_thread")) {
        log(QStringLiteral("exit_thread  tid=") + res[QStringLiteral("tid")].toVariant().toString()
            + QStringLiteral("  code=") + res[QStringLiteral("exitCode")].toVariant().toString(),
            LogKind::Event);
    } else if (ev == QStringLiteral("exit_process")) {
        log(QStringLiteral("exit_process  code=") + res[QStringLiteral("exitCode")].toVariant().toString(),
            LogKind::Event);
        setDebugState(QStringLiteral("exit"), res[QStringLiteral("exitCode")].toVariant().toString());
    } else if (ev == QStringLiteral("create_process")) {
        log(QStringLiteral("create_process  pid=") + res[QStringLiteral("pid")].toVariant().toString()
            + QStringLiteral("  base=") + fmtAddr(res[QStringLiteral("base")].toVariant().toString()),
            LogKind::Event);
    } else if (ev == QStringLiteral("output_debug_string")) {
        log(res[QStringLiteral("message")].toVariant().toString(), LogKind::Info);
    } else {
        QString line = QStringLiteral("continue -> ") + ev;
        for (const QString& k : res.keys()) {
            if (k == QStringLiteral("event")) continue;
            line += QStringLiteral("  ") + k + QLatin1Char('=') + res[k].toVariant().toString();
        }
        log(line, LogKind::Event);
    }

    if (res[QStringLiteral("stopped")].toBool(false) && ev != QStringLiteral("exit_process") && ev != QStringLiteral("exception")) {
        QString addr = res.contains(QStringLiteral("pc")) ? res[QStringLiteral("pc")].toVariant().toString() : res[QStringLiteral("address")].toVariant().toString();
        QString reason = res[QStringLiteral("reason")].toVariant().toString();
        QString details = fmtAddr(addr);
        if (!reason.isEmpty()) details += QStringLiteral(" (") + reason + QStringLiteral(")");
        setDebugState(QStringLiteral("pause"), details);
    }
}

