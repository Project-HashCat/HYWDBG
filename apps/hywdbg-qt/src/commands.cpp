#include "mainwindow.h"
#include <QFile>
#include <QMessageBox>

namespace {

bool isPe64Executable(const QString& path, QString* error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = file.errorString();
        return false;
    }

    QByteArray data = file.read(0x1000);
    const auto readU16 = [&data](qsizetype off) -> quint16 {
        return static_cast<quint8>(data[off])
             | (static_cast<quint16>(static_cast<quint8>(data[off + 1])) << 8);
    };
    const auto readU32 = [&data](qsizetype off) -> quint32 {
        return static_cast<quint8>(data[off])
             | (static_cast<quint32>(static_cast<quint8>(data[off + 1])) << 8)
             | (static_cast<quint32>(static_cast<quint8>(data[off + 2])) << 16)
             | (static_cast<quint32>(static_cast<quint8>(data[off + 3])) << 24);
    };

    if (data.size() < 0x40 || readU16(0) != 0x5A4D) {
        if (error) *error = QStringLiteral("not a PE executable");
        return false;
    }

    quint32 peOffset = readU32(0x3C);
    if (peOffset > 0x100000) {
        if (error) *error = QStringLiteral("invalid PE header offset");
        return false;
    }

    if (data.size() < static_cast<qsizetype>(peOffset + 6)) {
        file.seek(peOffset);
        data = file.read(6);
        peOffset = 0;
    }

    if (data.size() < static_cast<qsizetype>(peOffset + 6)
        || data.mid(peOffset, 4) != QByteArrayLiteral("PE\0\0")) {
        if (error) *error = QStringLiteral("invalid PE signature");
        return false;
    }

    constexpr quint16 kMachineAmd64 = 0x8664;
    return readU16(peOffset + 4) == kMachineAmd64;
}

} // namespace

void MainWindow::runCommand(const QString& line)
{
    log(QStringLiteral("hyw> ") + line, LogKind::Cmd);

    try {
        QStringList parts = line.trimmed().split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (parts.isEmpty()) return;
        QString c = parts[0].toLower();

        // help
        if (c == QStringLiteral("help")) {
            log(QStringLiteral(
                "Commands: help launch attach detach kill go/g/continue pause "
                "si/stepin/s so/stepover/n sout/stepout bp/bpset bc/bpclear bl/bplist "
                "mem/db/dd regs/r setreg threads modules stack/callstack proc/ps "
                "disasm/u wp/wpset wc/wpclear wl/wplist refresh/rf raw <method> [json]"),
                LogKind::Info);
            return;
        }

        // launch
        if (c == QStringLiteral("launch")) {
            QString exe = (parts.size() > 1) ? parts.mid(1).join(QLatin1Char(' ')) : QString();
            if (exe.isEmpty()) {
                exe = QFileDialog::getOpenFileName(this, QStringLiteral("Launch"), QString(),
                                                   QStringLiteral("Executables (*.exe);;All Files (*)"));
                if (exe.isEmpty()) return;
            }
            QString peError;
            if (!isPe64Executable(exe, &peError)) {
                QMessageBox::warning(this,
                                     QStringLiteral("HYWDbg"),
                                     QStringLiteral("Please use the 32-bit HYWDbg to debug this program."));
                log(QStringLiteral("Launch rejected: target is not a 64-bit PE")
                    + (peError.isEmpty() ? QString() : QStringLiteral(" (") + peError + QLatin1Char(')')),
                    LogKind::Warn);
                setStatus(QStringLiteral("Launch rejected: non-x64 target"));
                return;
            }
            setDebugState(QStringLiteral("starting"));
            startDaemon();
            QJsonObject p;
            p[QStringLiteral("path")] = exe;
            QJsonObject res = rpc(QStringLiteral("dbg.launch"), p).toObject();
            QString pidStr = res[QStringLiteral("pid")].toVariant().toString();
            log(QStringLiteral("Launched: pid=") + pidStr, LogKind::Ok);
            setStatus(QStringLiteral("Launched: ") + exe);
            // Feature 4: update pidLabel
            if (pidLabel) pidLabel->setText(QStringLiteral("PID: ") + pidStr);
            setDebugState(QStringLiteral("pause"));
            QTimer::singleShot(200, this, &MainWindow::refreshAll);
            return;
        }

        // attach
        if (c == QStringLiteral("attach")) {
            quint64 pid = 0;
            if (parts.size() > 1) {
                bool ok = false;
                pid = parts[1].toULongLong(&ok);
                if (!ok) pid = 0;
            }
            if (pid == 0) {
                // Open the enhanced attach dialog
                showAttachDialog();
                return;
            }
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
            return;
        }

        // detach
        if (c == QStringLiteral("detach")) {
            rpc(QStringLiteral("dbg.detach"), {});
            log(QStringLiteral("Detached"), LogKind::Ok);
            setStatus(QStringLiteral("Detached"));
            return;
        }

        // kill
        if (c == QStringLiteral("kill")) {
            rpc(QStringLiteral("dbg.kill"), {});
            log(QStringLiteral("Process killed"), LogKind::Warn);
            setStatus(QStringLiteral("Killed"));
            return;
        }

        // go / continue
        if (c == QStringLiteral("go") || c == QStringLiteral("g") || c == QStringLiteral("continue")) {
            setDebugState(QStringLiteral("running"));
            QJsonObject res = rpc(QStringLiteral("dbg.go"), {}).toObject();
            formatEventDetail(res);
            if (res[QStringLiteral("event")].toString() != QStringLiteral("exit_process")) refreshAll();
            return;
        }

        // pause
        if (c == QStringLiteral("pause")) {
            rpc(QStringLiteral("dbg.pause"), {});
            log(QStringLiteral("Paused"), LogKind::Warn);
            setDebugState(QStringLiteral("pause"));
            refreshAll();
            return;
        }

        // step in
        if (c == QStringLiteral("si") || c == QStringLiteral("stepin") || c == QStringLiteral("s")) {
            setDebugState(QStringLiteral("running"));
            QJsonObject res = rpc(QStringLiteral("dbg.stepInto"), {}).toObject();
            formatEventDetail(res);
            if (res[QStringLiteral("event")].toString() != QStringLiteral("exit_process")) refreshAll();
            return;
        }

        // step over
        if (c == QStringLiteral("so") || c == QStringLiteral("stepover") || c == QStringLiteral("n")) {
            setDebugState(QStringLiteral("running"));
            QJsonObject res = rpc(QStringLiteral("dbg.stepOver"), {}).toObject();
            formatEventDetail(res);
            if (res[QStringLiteral("event")].toString() != QStringLiteral("exit_process")) refreshAll();
            return;
        }

        // step out
        if (c == QStringLiteral("sout") || c == QStringLiteral("stepout")) {
            setDebugState(QStringLiteral("running"));
            QJsonObject res = rpc(QStringLiteral("dbg.stepOut"), {}).toObject();
            formatEventDetail(res);
            if (res[QStringLiteral("event")].toString() != QStringLiteral("exit_process")) refreshAll();
            return;
        }

        // bp / bpset
        if (c == QStringLiteral("bp") || c == QStringLiteral("bpset")) {
            if (parts.size() < 2) { log(QStringLiteral("Usage: bp <addr|symbol>"), LogKind::Warn); return; }
            QString resolved = resolveToAddr(parts[1]);
            if (resolved.isEmpty()) resolved = fmtAddr(parts[1]);
            QJsonObject p;
            p[QStringLiteral("addr")] = resolved;
            rpc(QStringLiteral("dbg.bpSet"), p);
            activeBpAddrs.insert(resolved);
            log(QStringLiteral("BP set at ") + resolved, LogKind::Ok);
            refreshBpList();
            return;
        }

        // bc / bpclear
        if (c == QStringLiteral("bc") || c == QStringLiteral("bpclear")) {
            if (parts.size() < 2) { log(QStringLiteral("Usage: bc <id|addr|all>"), LogKind::Warn); return; }
            QString arg = parts[1];
            if (arg.toLower() == QStringLiteral("all")) {
                QJsonObject p; p[QStringLiteral("all")] = true;
                rpc(QStringLiteral("dbg.bpClear"), p);
                activeBpAddrs.clear();
                log(QStringLiteral("All breakpoints cleared"), LogKind::Warn);
            } else {
                bool isId = false; arg.toInt(&isId);
                QJsonObject p;
                if (isId) p[QStringLiteral("id")]   = arg.toInt();
                else       p[QStringLiteral("addr")] = fmtAddr(arg);
                rpc(QStringLiteral("dbg.bpClear"), p);
                activeBpAddrs.remove(fmtAddr(arg));
                log(QStringLiteral("BP cleared: ") + arg, LogKind::Warn);
            }
            refreshBpList();
            return;
        }

        // bl / bplist
        if (c == QStringLiteral("bl") || c == QStringLiteral("bplist")) {
            refreshBpList();
            log(QStringLiteral("Breakpoints: ") + QString::number(bpTable->rowCount()), LogKind::Info);
            return;
        }

        // mem / db / dd
        if (c == QStringLiteral("mem") || c == QStringLiteral("db") || c == QStringLiteral("dd")) {
            if (parts.size() < 2) { log(QStringLiteral("Usage: mem <addr> [len]"), LogKind::Warn); return; }
            memAddrBar->setText(parts[1]);
            if (parts.size() >= 3) memLenBar->setText(parts[2]);
            refreshMem();
            return;
        }

        // regs / r
        if (c == QStringLiteral("regs") || c == QStringLiteral("r")) {
            refreshRegs();
            return;
        }

        // setreg
        if (c == QStringLiteral("setreg")) {
            if (parts.size() < 3) { log(QStringLiteral("Usage: setreg <reg> <value>"), LogKind::Warn); return; }
            QJsonObject p;
            p[QStringLiteral("reg")]   = parts[1];
            p[QStringLiteral("value")] = parts[2];
            rpc(QStringLiteral("dbg.setReg"), p);
            log(QStringLiteral("Set ") + parts[1] + QStringLiteral(" = ") + parts[2], LogKind::Ok);
            refreshRegs();
            return;
        }

        // threads
        if (c == QStringLiteral("threads")) { refreshThreads(); return; }

        // modules
        if (c == QStringLiteral("modules")) { refreshModules(); return; }

        // stack / callstack
        if (c == QStringLiteral("stack") || c == QStringLiteral("callstack")) {
            refreshCallStack(); return;
        }

        // proc / ps
        if (c == QStringLiteral("proc") || c == QStringLiteral("ps")) {
            QJsonArray procs = rpc(QStringLiteral("dbg.processList"), {}).toArray();
            log(QStringLiteral("Processes (") + QString::number(procs.size()) + QLatin1Char(')'),
                LogKind::Info);
            for (const QJsonValue& v : procs) {
                QJsonObject pr = v.toObject();
                log(QStringLiteral("  PID=") + pr[QStringLiteral("pid")].toVariant().toString()
                    + QStringLiteral("  ") + pr[QStringLiteral("name")].toVariant().toString()
                    + QStringLiteral("  ") + pr[QStringLiteral("path")].toVariant().toString(),
                    LogKind::Info);
            }
            return;
        }

        // disasm / u
        if (c == QStringLiteral("disasm") || c == QStringLiteral("u")) {
            if (parts.size() < 2) { log(QStringLiteral("Usage: disasm <addr|symbol>"), LogKind::Warn); return; }
            refreshDisasm(parts[1]);
            return;
        }

        // wp / wpset
        if (c == QStringLiteral("wp") || c == QStringLiteral("wpset")) {
            if (parts.size() < 3) { log(QStringLiteral("Usage: wp <addr> <size> [r|w|rw]"), LogKind::Warn); return; }
            QJsonObject p;
            p[QStringLiteral("addr")] = fmtAddr(parts[1]);
            p[QStringLiteral("size")] = parts[2].toInt();
            if (parts.size() >= 4) p[QStringLiteral("kind")] = parts[3];
            rpc(QStringLiteral("dbg.wpSet"), p);
            log(QStringLiteral("Watchpoint set at ") + fmtAddr(parts[1]), LogKind::Ok);
            return;
        }

        // wc / wpclear
        if (c == QStringLiteral("wc") || c == QStringLiteral("wpclear")) {
            QJsonObject p;
            if (parts.size() >= 2) p[QStringLiteral("id")] = parts[1].toInt();
            rpc(QStringLiteral("dbg.wpClear"), p);
            log(QStringLiteral("Watchpoint cleared"), LogKind::Warn);
            return;
        }

        // wl / wplist
        if (c == QStringLiteral("wl") || c == QStringLiteral("wplist")) {
            QJsonArray wps = rpc(QStringLiteral("dbg.wpList"), {}).toArray();
            log(QStringLiteral("Watchpoints (") + QString::number(wps.size()) + QLatin1Char(')'), LogKind::Info);
            for (int i = 0; i < wps.size(); ++i) {
                QJsonObject w = wps[i].toObject();
                log(QStringLiteral("  [") + QString::number(i)
                    + QStringLiteral("] addr=") + fmtAddr(w[QStringLiteral("addr")].toVariant().toString())
                    + QStringLiteral("  size=") + w[QStringLiteral("size")].toVariant().toString()
                    + QStringLiteral("  kind=") + w[QStringLiteral("kind")].toVariant().toString()
                    + QStringLiteral("  enabled=")
                    + (w[QStringLiteral("enabled")].toBool() ? QStringLiteral("yes") : QStringLiteral("no")),
                    LogKind::Info);
            }
            return;
        }

        // refresh / rf
        if (c == QStringLiteral("refresh") || c == QStringLiteral("rf")) {
            refreshAll(); return;
        }

        // raw <method> [json]
        if (c == QStringLiteral("raw")) {
            if (parts.size() < 2) { log(QStringLiteral("Usage: raw <method> [json]"), LogKind::Warn); return; }
            QString method = parts[1];
            QJsonObject params;
            if (parts.size() >= 3) {
                QString js = parts.mid(2).join(QLatin1Char(' '));
                QJsonParseError pe;
                QJsonDocument doc = QJsonDocument::fromJson(js.toUtf8(), &pe);
                if (pe.error == QJsonParseError::NoError && doc.isObject())
                    params = doc.object();
            }
            QJsonValue resVal = rpc(method, params);
            QJsonDocument doc;
            if (resVal.isArray()) doc = QJsonDocument(resVal.toArray());
            else doc = QJsonDocument(resVal.toObject());
            log(QStringLiteral("RAW ") + method + QStringLiteral(":\n")
                + doc.toJson(QJsonDocument::Indented),
                LogKind::Info);
            return;
        }

        // Last chance: try as address / symbol -> refreshDisasm
        {
            QString first = parts[0];
            bool looksHex = first.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)
                            || first.contains(QLatin1Char('.'));
            if (!looksHex) {
                bool allHex = !first.isEmpty();
                for (QChar ch : first)
                    if (!QString(QStringLiteral("0123456789abcdefABCDEF")).contains(ch))
                        { allHex = false; break; }
                if (allHex && first.size() >= 4) looksHex = true;
            }
            if (looksHex) {
                QString resolved = resolveToAddr(first);
                if (!resolved.isEmpty()) { refreshDisasm(resolved); return; }
            }
        }

        // Unknown
        log(QStringLiteral("unknown command: ") + c + QStringLiteral("  (type 'help')"), LogKind::Error);

    } catch (const std::exception& e) {
        log(QStringLiteral("Exception: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}
