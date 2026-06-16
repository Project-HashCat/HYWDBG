#include "mainwindow.h"

QString MainWindow::mnemonicCategory(const QString& m)
{
    QString lm = m.toLower();
    if (lm.startsWith(QLatin1String("call")))  return QStringLiteral("call");
    if (lm.startsWith(QLatin1String("ret")))   return QStringLiteral("ret");
    if (lm.startsWith(QLatin1String("j")))     return QStringLiteral("jmp");
    if (lm == QStringLiteral("nop"))           return QStringLiteral("nop");
    if (lm == QStringLiteral("push") || lm == QStringLiteral("pop") ||
        lm == QStringLiteral("pushf")|| lm == QStringLiteral("popf") ||
        lm == QStringLiteral("pushfd")||lm == QStringLiteral("popfd")||
        lm == QStringLiteral("pushfq")||lm == QStringLiteral("popfq")||
        lm == QStringLiteral("enter")|| lm == QStringLiteral("leave"))
        return QStringLiteral("stack");
    if (lm.startsWith(QLatin1String("mov")) || lm.startsWith(QLatin1String("lea")) ||
        lm == QStringLiteral("xchg")  || lm == QStringLiteral("bswap")  ||
        lm.startsWith(QLatin1String("cmov")))
        return QStringLiteral("mov");
    if (lm == QStringLiteral("and") || lm == QStringLiteral("or")  ||
        lm == QStringLiteral("xor") || lm == QStringLiteral("not") ||
        lm == QStringLiteral("shl") || lm == QStringLiteral("shr") ||
        lm == QStringLiteral("sar") || lm == QStringLiteral("rol") ||
        lm == QStringLiteral("ror") || lm == QStringLiteral("rcl") ||
        lm == QStringLiteral("rcr") || lm == QStringLiteral("test")||
        lm == QStringLiteral("cmp") || lm.startsWith(QLatin1String("bt")))
        return QStringLiteral("logic");
    if (lm == QStringLiteral("add") || lm == QStringLiteral("sub") ||
        lm == QStringLiteral("mul") || lm == QStringLiteral("div") ||
        lm == QStringLiteral("imul")|| lm == QStringLiteral("idiv")||
        lm == QStringLiteral("inc") || lm == QStringLiteral("dec") ||
        lm == QStringLiteral("neg") || lm == QStringLiteral("adc") ||
        lm == QStringLiteral("sbb") || lm.startsWith(QLatin1String("set")))
        return QStringLiteral("arith");
    return QStringLiteral("other");
}

QColor MainWindow::mnemonicColor(const QString& cat)
{
    if (cat == QStringLiteral("call"))  return QColor(0x4E, 0xC9, 0xF0);
    if (cat == QStringLiteral("ret"))   return QColor(0xF1, 0x4C, 0x4C);
    if (cat == QStringLiteral("jmp"))   return QColor(0xE8, 0xC0, 0x40);
    if (cat == QStringLiteral("nop"))   return QColor(0x60, 0x60, 0x70);
    if (cat == QStringLiteral("stack")) return QColor(0xC8, 0xA0, 0x60);
    if (cat == QStringLiteral("mov"))   return QColor(0xD4, 0xD4, 0xD4);
    if (cat == QStringLiteral("logic")) return QColor(0x9C, 0xDC, 0xFE);
    if (cat == QStringLiteral("arith")) return QColor(0xB5, 0xCE, 0xA8);
    return QColor(0xD4, 0xD4, 0xD4);
}

void MainWindow::addDisasmRow(int row,
                              const QString& addrFmt,
                              const QString& bytesStr,
                              const QString& mnemonic,
                              const QString& cat,
                              const QString& operands,
                              const QString& comment,
                              bool isRip,
                              bool hasBp)
{
    // x64dbg-style palette
    static const QColor kRipBg  (0x08, 0x1A, 0x38);
    static const QColor kBpBg   (0x38, 0x08, 0x08);
    static const QColor kDefBg  (0x12, 0x12, 0x12);
    static const QColor kRipArrow(0x00, 0xD4, 0xFF);
    static const QColor kBpDot  (0xFF, 0x44, 0x44);
    static const QColor kRipAddr (0x00, 0xCF, 0xFF);
    static const QColor kNormAddr(0x9B, 0xB8, 0xD8);
    static const QColor kBpAddr  (0xFF, 0x88, 0x66);
    static const QColor kBytes   (0x4E, 0x68, 0x78);
    static const QColor kRipBytes(0x5E, 0x88, 0x98);
    static const QColor kRipOp   (0xFF, 0xFF, 0xFF);
    static const QColor kNormOp  (0xC8, 0xD8, 0xE8);
    static const QColor kComment (0x4A, 0x90, 0x60);
    static const QColor kBmBg    (0x2A, 0x2A, 0x40);

    QString rawAddr = addrFmt.split(QLatin1Char(' ')).first();
    QString finalAddrFmt = addrFmt;
    if (userLabels.contains(rawAddr)) {
        finalAddrFmt = rawAddr + QStringLiteral(" <") + userLabels[rawAddr] + QStringLiteral(">");
    }

    QString finalComment = comment;
    if (userComments.contains(rawAddr)) {
        finalComment = userComments[rawAddr];
    }

    bool isBm = bookmarks.contains(rawAddr);
    QColor rowBg = isRip ? kRipBg : (hasBp ? kBpBg : (isBm ? kBmBg : kDefBg));

    // col 0: marker
    // U+279C arrow: \xe2\x9e\x9c
    // U+25CF bullet: \xe2\x97\x8f
    QString marker;
    QColor markerColor;
    if (isRip) {
        marker = QString::fromUtf8("\xe2\x9e\x9c");
        markerColor = kRipArrow;
    } else if (hasBp) {
        marker = QString::fromUtf8("\xe2\x97\x8f");
        markerColor = kBpDot;
    } else {
        markerColor = kDefBg;
    }

    auto* c0 = tableItem(marker, markerColor);
    c0->setBackground(rowBg);
    c0->setTextAlignment(Qt::AlignCenter);
    disasmTable->setItem(row, 0, c0);

    QColor addrColor = isRip ? kRipAddr : (hasBp ? kBpAddr : kNormAddr);
    auto* c1 = tableItem(finalAddrFmt, addrColor, isRip);
    c1->setBackground(rowBg);
    disasmTable->setItem(row, 1, c1);

    QColor bytesColor = isRip ? kRipBytes : kBytes;
    auto* c2 = tableItem(bytesStr, bytesColor);
    c2->setBackground(rowBg);
    disasmTable->setItem(row, 2, c2);

    QColor mnColor = isRip ? kRipOp : mnemonicColor(cat);
    auto* c3 = tableItem(mnemonic, mnColor, isRip);
    c3->setBackground(rowBg);
    disasmTable->setItem(row, 3, c3);

    QColor opColor = isRip ? kRipOp : kNormOp;
    auto* c4 = tableItem(operands, opColor);
    c4->setBackground(rowBg);
    disasmTable->setItem(row, 4, c4);

    auto* c5 = tableItem(finalComment, kComment);
    c5->setBackground(rowBg);
    disasmTable->setItem(row, 5, c5);
}

void MainWindow::updateDisasmRowHighlight(int row, bool isRip, bool hasBp)
{
    if (row < 0 || row >= disasmTable->rowCount()) return;
    auto getCell = [&](int c) -> QString {
        auto* it = disasmTable->item(row, c);
        return it ? it->text() : QString();
    };
    QString addrFmt  = getCell(1);
    QString bytesStr = getCell(2);
    QString mnemonic = getCell(3);
    QString operands = getCell(4);
    QString comment  = getCell(5);
    addDisasmRow(row, addrFmt, bytesStr, mnemonic, mnemonicCategory(mnemonic),
                 operands, comment, isRip, hasBp);
}

QString MainWindow::resolveToAddr(const QString& expr)
{
    QString s = expr.trimmed();
    if (s.isEmpty()) return {};

    // Pure hex literal (only if starts with 0x/0X or consists entirely of hex digits)
    bool isHexLiteral = s.startsWith(QLatin1String("0x"), Qt::CaseInsensitive);
    if (!isHexLiteral) {
        bool allDigits = true;
        for (int i = 0; i < s.length(); ++i) {
            if (!s[i].isDigit()) {
                allDigits = false;
                break;
            }
        }
        if (allDigits && !s.isEmpty()) isHexLiteral = true;
    }
    if (isHexLiteral) {
        QString t = s;
        if (t.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)) t = t.mid(2);
        bool ok = false;
        t.toULongLong(&ok, 16);
        if (ok && !t.isEmpty()) return fmtAddr(s);
    }

    // Symbol - module.symbol or bare symbol
    QString modPart, symPart;
    int dot = s.indexOf(QLatin1Char('.'));
    if (dot >= 0) {
        modPart = s.left(dot);
        symPart = s.mid(dot + 1);
    } else {
        symPart = s;
    }

    try {
        QJsonObject p;
        if (!modPart.isEmpty()) p[QStringLiteral("module")] = modPart;
        p[QStringLiteral("symbol")] = symPart;
        QJsonObject res = rpc(QStringLiteral("dbg.resolveSymbol"), p).toObject();
        QString addr = res[QStringLiteral("addr")].toString();
        if (!addr.isEmpty()) return fmtAddr(addr);
    } catch (...) {}

    return {};
}

void MainWindow::refreshDisasm(const QString& addr)
{
    // Resolve address
    QString resolved;
    QString lower = addr.trimmed().toLower();
    if (lower == QStringLiteral("rip") ||
        lower == QStringLiteral("pc")  ||
        lower == QStringLiteral("eip")) {
        resolved = rip.isEmpty() ? addr : rip;
    } else {
        resolved = resolveToAddr(addr);
        if (resolved.isEmpty()) resolved = addr;
    }

    quint64 targetVal = parseAddr(resolved);

    // Try in-place update: scan all rows for old RIP marker
    // Arrow U+279C as byte escapes in string literal:
    int oldRipRow = -1;
    int targetRow = -1;
    QString ripArrow = QString::fromUtf8("\xe2\x9e\x9c");

    for (int r = 0; r < disasmTable->rowCount(); ++r) {
        auto* m0 = disasmTable->item(r, 0);
        auto* m1 = disasmTable->item(r, 1);
        if (m0 && m0->text() == ripArrow) oldRipRow = r;
        if (m1 && parseAddr(m1->text()) == targetVal) targetRow = r;
    }

    if (targetRow >= 0) {
        if (oldRipRow >= 0 && oldRipRow != targetRow) {
            auto* prevAddr = disasmTable->item(oldRipRow, 1);
            bool prevHasBp = prevAddr && activeBpAddrs.contains(fmtAddr(prevAddr->text()));
            updateDisasmRowHighlight(oldRipRow, false, prevHasBp);
        }
        bool nowHasBp = activeBpAddrs.contains(fmtAddr(resolved));
        updateDisasmRowHighlight(targetRow, true, nowHasBp);
        disasmTable->scrollToItem(disasmTable->item(targetRow, 0),
                                  QAbstractItemView::PositionAtCenter);
        return;
    }

    // Full reload via RPC
    try {
        QJsonObject p;
        p[QStringLiteral("addr")]  = resolved;
        p[QStringLiteral("count")] = 80;
        QJsonArray instrs = rpc(QStringLiteral("dbg.disasm"), p).toArray();

        disasmTable->setRowCount(0);
        int ripRow = -1;

        for (int i = 0; i < instrs.size(); ++i) {
            QJsonObject ins  = instrs[i].toObject();
            QString addrFmt  = fmtAddr(ins[QStringLiteral("addr")].toVariant().toString());
            QString bytesStr = spacedHex(ins[QStringLiteral("bytes")].toVariant().toString());
            QString text     = ins[QStringLiteral("text")].toVariant().toString().trimmed();
            QString mnemonic;
            QString operands;
            int spaceIdx = text.indexOf(QLatin1Char(' '));
            if (spaceIdx >= 0) {
                mnemonic = text.left(spaceIdx).trimmed();
                operands = text.mid(spaceIdx + 1).trimmed();
            } else {
                mnemonic = text;
            }
            QString comment  = QString();
            QString cat      = mnemonicCategory(mnemonic);
            bool isRip       = (parseAddr(addrFmt) == parseAddr(rip));
            bool hasBp       = activeBpAddrs.contains(addrFmt);

            int row = disasmTable->rowCount();
            disasmTable->insertRow(row);
            disasmTable->setRowHeight(row, 20);
            addDisasmRow(row, addrFmt, bytesStr, mnemonic, cat, operands, comment, isRip, hasBp);
            if (isRip) ripRow = row;
        }

        if (ripRow >= 0)
            disasmTable->scrollToItem(disasmTable->item(ripRow, 0),
                                      QAbstractItemView::PositionAtCenter);
    } catch (const std::exception& e) {
        log(QStringLiteral("refreshDisasm: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::appendDisasm(const QString& fromAddr)
{
    if (disasmFetchingMore) return;
    disasmFetchingMore = true;
    auto guard = qScopeGuard([this]() { disasmFetchingMore = false; });

    try {
        QJsonObject p;
        p[QStringLiteral("addr")]  = fmtAddr(fromAddr);
        p[QStringLiteral("count")] = 62;
        QJsonArray instrs = rpc(QStringLiteral("dbg.disasm"), p).toArray();

        // Skip first row (already in table)
        for (int i = 1; i < instrs.size(); ++i) {
            QJsonObject ins  = instrs[i].toObject();
            QString addrFmt  = fmtAddr(ins[QStringLiteral("addr")].toVariant().toString());
            QString bytesStr = spacedHex(ins[QStringLiteral("bytes")].toVariant().toString());
            QString text     = ins[QStringLiteral("text")].toVariant().toString().trimmed();
            QString mnemonic;
            QString operands;
            int spaceIdx = text.indexOf(QLatin1Char(' '));
            if (spaceIdx >= 0) {
                mnemonic = text.left(spaceIdx).trimmed();
                operands = text.mid(spaceIdx + 1).trimmed();
            } else {
                mnemonic = text;
            }
            QString comment  = QString();
            bool isRip       = (parseAddr(addrFmt) == parseAddr(rip));
            bool hasBp       = activeBpAddrs.contains(addrFmt);

            int row = disasmTable->rowCount();
            disasmTable->insertRow(row);
            disasmTable->setRowHeight(row, 20);
            addDisasmRow(row, addrFmt, bytesStr, mnemonic, mnemonicCategory(mnemonic),
                         operands, comment, isRip, hasBp);
        }
    } catch (const std::exception& e) {
        log(QStringLiteral("appendDisasm: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

