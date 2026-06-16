#include "mainwindow.h"

void MainWindow::refreshMem()
{
    QString rawAddr = memAddrBar->text().trimmed();
    if (rawAddr.isEmpty()) return;

    QString resolved = resolveToAddr(rawAddr);
    if (resolved.isEmpty()) resolved = fmtAddr(rawAddr);

    QString rawLen = memLenBar->text().trimmed();
    bool ok = false;
    quint64 len = rawLen.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)
                  ? rawLen.mid(2).toULongLong(&ok, 16)
                  : rawLen.toULongLong(&ok, 10);
    if (!ok || len == 0) len = 0x100;

    try {
        QJsonObject p;
        p[QStringLiteral("addr")] = resolved;
        p[QStringLiteral("size")]  = static_cast<qint64>(len);
        QJsonObject res = rpc(QStringLiteral("dbg.readMem"), p).toObject();
        QString hexData = res[QStringLiteral("hex")].toVariant().toString();

        QByteArray bytes = QByteArray::fromHex(hexData.toUtf8());
        quint64 base     = parseAddr(resolved);
        memView->setRowCount(0);
        
        for (int i = 0; i < bytes.size(); i += 16) {
            int row = memView->rowCount();
            memView->insertRow(row);
            memView->setRowHeight(row, 20);
            
            // Address column
            QString addrStr = QString::number(base + static_cast<quint64>(i), 16)
                              .toUpper().rightJustified(16, QLatin1Char('0'));
            auto* addrItem = tableItem(addrStr, QColor(0x9CDCFE));
            memView->setItem(row, 0, addrItem);

            // Hex bytes
            QByteArray slice = bytes.mid(i, 16);
            for (int j = 0; j < 16; ++j) {
                if (j < slice.size()) {
                    QString byteStr = QString::number(static_cast<quint8>(slice[j]), 16)
                                      .toUpper().rightJustified(2, QLatin1Char('0'));
                    auto* byteItem = tableItem(byteStr);
                    memView->setItem(row, j + 1, byteItem);
                } else {
                    auto* emptyItem = tableItem(QStringLiteral(""));
                    memView->setItem(row, j + 1, emptyItem);
                }
            }

            // ASCII
            QString ascii;
            for (int j = 0; j < slice.size(); ++j) {
                uchar c = static_cast<uchar>(slice[j]);
                ascii += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar(QLatin1Char('.'));
            }
            auto* asciiItem = tableItem(ascii, QColor(0xCE, 0x91, 0x78));
            memView->setItem(row, 17, asciiItem);
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshMem: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshStack()
{
    if (!stackMemTable) return;
    if (rsp.isEmpty()) return;

    quint64 rspVal = parseAddr(rsp);
    // Read from RSP - 0x10 for context, total 0x80 bytes
    quint64 baseAddr = (rspVal >= 0x10) ? (rspVal - 0x10) : rspVal;
    quint64 readSize = 0x80;

    try {
        QJsonObject p;
        p[QStringLiteral("addr")] = fmtAddr(QString::number(baseAddr, 16));
        p[QStringLiteral("size")] = static_cast<qint64>(readSize);
        QJsonObject res = rpc(QStringLiteral("dbg.readMem"), p).toObject();
        QString hexData = res[QStringLiteral("hex")].toVariant().toString();
        QByteArray bytes = QByteArray::fromHex(hexData.toUtf8());

        stackMemTable->setRowCount(0);
        int chunkSize = 8; // 64-bit pointer size
        for (int i = 0; i + chunkSize <= bytes.size(); i += chunkSize) {
            quint64 entryAddr = baseAddr + static_cast<quint64>(i);
            // Build 8-byte little-endian value
            quint64 val = 0;
            for (int b = 0; b < chunkSize; ++b)
                val |= (static_cast<quint64>(static_cast<quint8>(bytes[i + b])) << (8 * b));

            QString addrStr = QStringLiteral("0x") +
                              QString::number(entryAddr, 16).toUpper().rightJustified(16, QLatin1Char('0'));
            QString valStr  = QStringLiteral("0x") +
                              QString::number(val, 16).toUpper().rightJustified(16, QLatin1Char('0'));
            QString ascii;
            for (int b = 0; b < chunkSize; ++b) {
                uchar c = static_cast<uchar>(bytes[i + b]);
                ascii += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar(QLatin1Char('.'));
            }

            int row = stackMemTable->rowCount();
            stackMemTable->insertRow(row);
            stackMemTable->setRowHeight(row, 20);

            bool isRspRow = (entryAddr == rspVal);
            QColor addrColor = isRspRow ? QColor(0x00, 0xCF, 0xFF) : QColor(0x9B, 0xB8, 0xD8);
            QColor valColor  = isRspRow ? QColor(0xFF, 0xFF, 0xFF) : QColor(0xD4, 0xD4, 0xD4);
            QColor ascColor  = QColor(0x70, 0x80, 0x70);
            QColor rowBg     = isRspRow ? QColor(0x08, 0x2A, 0x18) : QColor(0x12, 0x12, 0x12);

            auto* a0 = tableItem(addrStr, addrColor, isRspRow);
            auto* a1 = tableItem(valStr,  valColor,  isRspRow);
            auto* a2 = tableItem(ascii,   ascColor);
            a0->setBackground(rowBg);
            a1->setBackground(rowBg);
            a2->setBackground(rowBg);
            stackMemTable->setItem(row, 0, a0);
            stackMemTable->setItem(row, 1, a1);
            stackMemTable->setItem(row, 2, a2);

            if (isRspRow)
                stackMemTable->scrollToItem(a0, QAbstractItemView::PositionAtCenter);
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshStack: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::nopOutAt(const QString& addr, int count)
{
    if (count <= 0) return;
    QByteArray nops(count, static_cast<char>(0x90));
    QString hexStr = QString::fromUtf8(nops.toHex());
    try {
        QString resolved = resolveToAddr(addr);
        if (resolved.isEmpty()) resolved = fmtAddr(addr);

        QJsonObject rp;
        rp[QStringLiteral("addr")] = resolved;
        rp[QStringLiteral("size")] = count;
        QJsonObject res = rpc(QStringLiteral("dbg.readMem"), rp).toObject();
        QString origHex = res[QStringLiteral("hex")].toVariant().toString();

        QJsonObject p;
        p[QStringLiteral("addr")] = resolved;
        p[QStringLiteral("hex")]  = hexStr;
        rpc(QStringLiteral("dbg.writeMem"), p);

        recordPatch(resolved, origHex, hexStr);

        log(QStringLiteral("NOPed ") + QString::number(count)
            + QStringLiteral(" bytes at ") + resolved, LogKind::Ok);
        refreshDisasm(resolved);
    } catch (const std::exception& e) {
        log(QStringLiteral("nopOutAt: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::editMemByte(int row, int col, const QString& hexStr)
{
    if (!memView) return;
    auto* addrItem = memView->item(row, 0);
    if (!addrItem) return;
    
    quint64 baseAddr = parseAddr(addrItem->text());
    quint64 byteAddr = baseAddr + (col - 1);
    QString addr = fmtAddr(QString::number(byteAddr, 16));
    
    try {
        QJsonObject rp;
        rp[QStringLiteral("addr")] = addr;
        rp[QStringLiteral("size")] = 1;
        QJsonObject res = rpc(QStringLiteral("dbg.readMem"), rp).toObject();
        QString origHex = res[QStringLiteral("hex")].toVariant().toString();

        QJsonObject p;
        p[QStringLiteral("addr")] = addr;
        p[QStringLiteral("hex")] = hexStr;
        rpc(QStringLiteral("dbg.writeMem"), p);

        recordPatch(addr, origHex, hexStr);

        log(QStringLiteral("Edited byte at ") + addr, LogKind::Ok);
        refreshMem();
    } catch (const std::exception& e) {
        log(QStringLiteral("editMemByte: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::recordPatch(const QString& addr, const QString& origBytes, const QString& newBytes)
{
    if (!patches.contains(addr)) {
        PatchRecord rec;
        rec.addr = addr;
        rec.origBytes = origBytes;
        rec.newBytes = newBytes;
        patches.insert(addr, rec);
    } else {
        patches[addr].newBytes = newBytes;
    }
    refreshPatchesList();
}

void MainWindow::revertPatch(const QString& addr)
{
    if (!patches.contains(addr)) return;
    PatchRecord rec = patches[addr];
    try {
        QJsonObject p;
        p[QStringLiteral("addr")] = rec.addr;
        p[QStringLiteral("hex")] = rec.origBytes;
        rpc(QStringLiteral("dbg.writeMem"), p);
        
        patches.remove(addr);
        log(QStringLiteral("Reverted patch at ") + addr, LogKind::Ok);
        
        refreshPatchesList();
        refreshDisasm(rec.addr);
        refreshMem();
    } catch (const std::exception& e) {
        log(QStringLiteral("revertPatch: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::refreshPatchesList()
{
    if (!patchTable) return;
    patchTable->setRowCount(0);
    for (auto it = patches.begin(); it != patches.end(); ++it) {
        int row = patchTable->rowCount();
        patchTable->insertRow(row);
        
        auto* addrItem = tableItem(it.value().addr, QColor(0x9CDCFE));
        auto* oldItem = tableItem(it.value().origBytes, QColor(0xCE, 0x91, 0x78));
        auto* newItem = tableItem(it.value().newBytes, QColor(0xB5, 0xCE, 0xA8));
        auto* stateItem = tableItem(QStringLiteral("Applied"), QColor(0x00, 0xFF, 0x00));
        
        patchTable->setItem(row, 0, addrItem);
        patchTable->setItem(row, 1, oldItem);
        patchTable->setItem(row, 2, newItem);
        patchTable->setItem(row, 3, stateItem);
    }
}

