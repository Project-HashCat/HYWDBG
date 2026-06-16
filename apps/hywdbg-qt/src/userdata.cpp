#include "mainwindow.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QInputDialog>

void MainWindow::loadProject()
{
    QFile file(QStringLiteral("project.hywdb"));
    if (!file.open(QIODevice::ReadOnly))
        return;

    QByteArray data = file.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) return;

    QJsonObject obj = doc.object();
    
    QJsonObject comments = obj[QStringLiteral("comments")].toObject();
    for (auto it = comments.begin(); it != comments.end(); ++it) {
        userComments.insert(it.key(), it.value().toString());
    }

    QJsonObject labels = obj[QStringLiteral("labels")].toObject();
    for (auto it = labels.begin(); it != labels.end(); ++it) {
        userLabels.insert(it.key(), it.value().toString());
    }

    QJsonArray bms = obj[QStringLiteral("bookmarks")].toArray();
    for (int i = 0; i < bms.size(); ++i) {
        bookmarks.insert(bms[i].toString());
    }

    QJsonArray patchArr = obj[QStringLiteral("patches")].toArray();
    for (int i = 0; i < patchArr.size(); ++i) {
        QJsonObject p = patchArr[i].toObject();
        PatchRecord rec;
        rec.addr = p[QStringLiteral("addr")].toString();
        rec.origBytes = p[QStringLiteral("origBytes")].toString();
        rec.newBytes = p[QStringLiteral("newBytes")].toString();
        patches.insert(rec.addr, rec);
    }
    refreshPatchesList();

    // Refresh bookmark table
    if (bookmarkTable) {
        bookmarkTable->setRowCount(0);
        int row = 0;
        for (const QString& addr : bookmarks) {
            bookmarkTable->insertRow(row);
            bookmarkTable->setItem(row, 0, tableItem(addr, QColor(0x9B, 0xB8, 0xD8)));
            bookmarkTable->setItem(row, 1, tableItem(userLabels.value(addr, QString()), QColor(0xD4, 0xD4, 0xD4)));
            bookmarkTable->setItem(row, 2, tableItem(userComments.value(addr, QString()), QColor(0x4A, 0x90, 0x60)));
            row++;
        }
    }
}

void MainWindow::saveProject()
{
    QJsonObject obj;

    QJsonObject comments;
    for (auto it = userComments.begin(); it != userComments.end(); ++it) {
        comments.insert(it.key(), it.value());
    }
    obj[QStringLiteral("comments")] = comments;

    QJsonObject labels;
    for (auto it = userLabels.begin(); it != userLabels.end(); ++it) {
        labels.insert(it.key(), it.value());
    }
    obj[QStringLiteral("labels")] = labels;

    QJsonArray bms;
    for (const QString& addr : bookmarks) {
        bms.append(addr);
    }
    obj[QStringLiteral("bookmarks")] = bms;

    QJsonArray patchArr;
    for (auto it = patches.begin(); it != patches.end(); ++it) {
        QJsonObject p;
        p[QStringLiteral("addr")] = it.value().addr;
        p[QStringLiteral("origBytes")] = it.value().origBytes;
        p[QStringLiteral("newBytes")] = it.value().newBytes;
        patchArr.append(p);
    }
    obj[QStringLiteral("patches")] = patchArr;

    QFile file(QStringLiteral("project.hywdb"));
    if (file.open(QIODevice::WriteOnly)) {
        QJsonDocument doc(obj);
        file.write(doc.toJson());
    }
}

void MainWindow::addBookmark(const QString& addr)
{
    QString rawAddr = addr.split(QLatin1Char(' ')).first();
    bookmarks.insert(rawAddr);
    saveProject();
    if (bookmarkTable) {
        int row = bookmarkTable->rowCount();
        bookmarkTable->insertRow(row);
        bookmarkTable->setItem(row, 0, tableItem(rawAddr, QColor(0x9B, 0xB8, 0xD8)));
        bookmarkTable->setItem(row, 1, tableItem(userLabels.value(rawAddr, QString()), QColor(0xD4, 0xD4, 0xD4)));
        bookmarkTable->setItem(row, 2, tableItem(userComments.value(rawAddr, QString()), QColor(0x4A, 0x90, 0x60)));
    }
}

void MainWindow::removeBookmark(const QString& addr)
{
    QString rawAddr = addr.split(QLatin1Char(' ')).first();
    bookmarks.remove(rawAddr);
    saveProject();
    if (bookmarkTable) {
        for (int row = 0; row < bookmarkTable->rowCount(); ++row) {
            auto* it = bookmarkTable->item(row, 0);
            if (it && it->text() == rawAddr) {
                bookmarkTable->removeRow(row);
                break;
            }
        }
    }
}

void MainWindow::editComment(const QString& addr)
{
    QString rawAddr = addr.split(QLatin1Char(' ')).first();
    bool ok;
    QString cur = userComments.value(rawAddr, QString());
    QString text = QInputDialog::getText(this, QStringLiteral("Edit Comment"),
                                         QStringLiteral("Comment for %1:").arg(rawAddr),
                                         QLineEdit::Normal,
                                         cur, &ok);
    if (ok) {
        if (text.isEmpty()) {
            userComments.remove(rawAddr);
        } else {
            userComments.insert(rawAddr, text);
        }
        saveProject();
        refreshDisasm(disasmAddrBar->text());
        
        // Update bookmark table if it exists
        if (bookmarkTable && bookmarks.contains(rawAddr)) {
            for (int row = 0; row < bookmarkTable->rowCount(); ++row) {
                auto* it = bookmarkTable->item(row, 0);
                if (it && it->text() == rawAddr) {
                    bookmarkTable->setItem(row, 2, tableItem(text, QColor(0x4A, 0x90, 0x60)));
                    break;
                }
            }
        }
    }
}

void MainWindow::editLabel(const QString& addr)
{
    QString rawAddr = addr.split(QLatin1Char(' ')).first();
    bool ok;
    QString cur = userLabels.value(rawAddr, QString());
    QString text = QInputDialog::getText(this, QStringLiteral("Edit Label"),
                                         QStringLiteral("Label for %1:").arg(rawAddr),
                                         QLineEdit::Normal,
                                         cur, &ok);
    if (ok) {
        if (text.isEmpty()) {
            userLabels.remove(rawAddr);
        } else {
            userLabels.insert(rawAddr, text);
        }
        saveProject();
        refreshDisasm(disasmAddrBar->text());
        
        // Update bookmark table if it exists
        if (bookmarkTable && bookmarks.contains(rawAddr)) {
            for (int row = 0; row < bookmarkTable->rowCount(); ++row) {
                auto* it = bookmarkTable->item(row, 0);
                if (it && it->text() == rawAddr) {
                    bookmarkTable->setItem(row, 1, tableItem(text, QColor(0xD4, 0xD4, 0xD4)));
                    break;
                }
            }
        }
    }
}
