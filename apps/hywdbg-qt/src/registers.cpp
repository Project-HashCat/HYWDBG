#include "mainwindow.h"

void MainWindow::refreshRegs()
{
    try {
        QJsonObject res  = rpc(QStringLiteral("dbg.regs"), {}).toObject();
        QJsonObject regs = res[QStringLiteral("registers")].toObject();

        // Update rip and rsp
        QString newRip, newRsp;
        if (regs.contains(QStringLiteral("rip")))      newRip = regs[QStringLiteral("rip")].toString();
        else if (regs.contains(QStringLiteral("pc")))   newRip = regs[QStringLiteral("pc")].toString();
        else if (regs.contains(QStringLiteral("eip")))  newRip = regs[QStringLiteral("eip")].toString();
        if (!newRip.isEmpty()) rip = fmtAddr(newRip);

        if (regs.contains(QStringLiteral("rsp")))      newRsp = regs[QStringLiteral("rsp")].toString();
        else if (regs.contains(QStringLiteral("esp")))  newRsp = regs[QStringLiteral("esp")].toString();
        if (!newRsp.isEmpty()) rsp = fmtAddr(newRsp);

        // Feature 4: update ripLabel
        if (ripLabel && !rip.isEmpty())
            ripLabel->setText(QStringLiteral("RIP: ") + rip);

        // Priority display order
        QStringList priority = {
            QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"), QStringLiteral("rdx"),
            QStringLiteral("rsi"), QStringLiteral("rdi"), QStringLiteral("rsp"), QStringLiteral("rbp"),
            QStringLiteral("r8"),  QStringLiteral("r9"),  QStringLiteral("r10"), QStringLiteral("r11"),
            QStringLiteral("r12"), QStringLiteral("r13"), QStringLiteral("r14"), QStringLiteral("r15"),
            QStringLiteral("rip"), QStringLiteral("rflags"), QStringLiteral("eflags"),
            QStringLiteral("cs"),  QStringLiteral("ss"),  QStringLiteral("ds"),
            QStringLiteral("es"),  QStringLiteral("fs"),  QStringLiteral("gs"),
            QStringLiteral("xmm0"),QStringLiteral("xmm1"),QStringLiteral("xmm2"),QStringLiteral("xmm3")
        };

        QStringList allKeys = regs.keys();
        QStringList ordered;
        for (const QString& k : priority)
            if (allKeys.contains(k)) ordered << k;
        for (const QString& k : allKeys)
            if (!ordered.contains(k)) ordered << k;

        // Collect new values for change tracking (feature 3)
        QMap<QString, QString> newRegValues;
        for (const QString& k : ordered)
            newRegValues[k] = regs[k].toString();

        // Track flags decode target
        QString flagsRegName;
        QString flagsRegVal;

        regTable->setRowCount(0);
        for (const QString& k : ordered) {
            QString val = regs[k].toString();
            int row = regTable->rowCount();
            regTable->insertRow(row);
            regTable->setRowHeight(row, 20);
            bool isPC = (k == QStringLiteral("rip") || k == QStringLiteral("eip")
                      || k == QStringLiteral("pc"));
            regTable->setItem(row, 0, tableItem(k,
                isPC ? QColor(0x00, 0xCF, 0xFF) : QColor(0x9C, 0xDC, 0xFE), isPC));
            regTable->setItem(row, 1, tableItem(val,
                isPC ? QColor(0xFF, 0xFF, 0xFF) : QColor(0xD4, 0xD4, 0xD4)));

            // Feature 3: change indicator
            QString changedText;
            QColor  changedColor(0x60, 0x60, 0x60);
            if (prevRegValues.contains(k) && prevRegValues[k] != val) {
                // U+25CF bullet: \xe2\x97\x8f in red/orange
                changedText  = QString::fromUtf8("\xe2\x97\x8f");
                changedColor = QColor(0xFF, 0x60, 0x40);
            }
            regTable->setItem(row, 2, tableItem(changedText, changedColor));

            // Track flags register
            if (k == QStringLiteral("rflags") || k == QStringLiteral("eflags")) {
                flagsRegName = k;
                flagsRegVal  = val;
            }
        }

        // Feature 5: EFLAGS decode
        if (!flagsRegName.isEmpty() && !flagsRegVal.isEmpty()) {
            QString hexVal = flagsRegVal;
            if (hexVal.startsWith(QLatin1String("0x"), Qt::CaseInsensitive))
                hexVal = hexVal.mid(2);
            bool ok2 = false;
            quint64 flags = hexVal.toULongLong(&ok2, 16);
            if (ok2) {
                QStringList setFlags;
                if (flags & (1ULL <<  0)) setFlags << QStringLiteral("CF");
                if (flags & (1ULL <<  2)) setFlags << QStringLiteral("PF");
                if (flags & (1ULL <<  4)) setFlags << QStringLiteral("AF");
                if (flags & (1ULL <<  6)) setFlags << QStringLiteral("ZF");
                if (flags & (1ULL <<  7)) setFlags << QStringLiteral("SF");
                if (flags & (1ULL <<  8)) setFlags << QStringLiteral("TF");
                if (flags & (1ULL <<  9)) setFlags << QStringLiteral("IF");
                if (flags & (1ULL << 10)) setFlags << QStringLiteral("DF");
                if (flags & (1ULL << 11)) setFlags << QStringLiteral("OF");
                QString decoded = setFlags.join(QLatin1Char(' '));

                int flagRow = regTable->rowCount();
                regTable->insertRow(flagRow);
                regTable->setRowHeight(flagRow, 20);
                QColor flagYellow(0xE8, 0xC8, 0x40);
                regTable->setItem(flagRow, 0, tableItem(QStringLiteral("  flags"), flagYellow));
                regTable->setItem(flagRow, 1, tableItem(decoded, flagYellow));
                regTable->setItem(flagRow, 2, tableItem(QString(), QColor(0x60, 0x60, 0x60)));
            }
        }

        // Feature 3: save current values as previous for next call
        prevRegValues = newRegValues;

    } catch (const std::exception& e) {
        log(QStringLiteral("refreshRegs: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

