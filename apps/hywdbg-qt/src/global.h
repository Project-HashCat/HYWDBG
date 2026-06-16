#pragma once
#include <QApplication>
#include <QMainWindow>
#include <QDockWidget>
#include <QSplitter>
#include <QTableWidget>
#include <QHeaderView>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QToolBar>
#include <QMenuBar>
#include <QMenu>
#include <QComboBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStatusBar>
#include <QProcess>
#include <QTcpSocket>
#include <QFileDialog>
#include <QInputDialog>
#include <QScrollBar>
#include <QTimer>
#include <QFont>
#include <QColor>
#include <QPalette>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QJsonParseError>
#include <QClipboard>
#include <QScopeGuard>
#include <QAbstractItemView>
#include <QDateTime>
#include <QSet>
#include <QMap>
#include <QStringList>
#include <QKeyEvent>
#include <QAction>
#include <QStyle>
#include <QStyleFactory>
#include <QFileInfo>
#include <QShortcut>
#include <QCompleter>
#include <QDialog>
#include <QDialogButtonBox>
#include <stdexcept>
#include <cstdint>

// Free helper functions
// -------------------------------------------------------------------

inline QString fmtAddr(const QString& raw)
{
    QString s = raw.trimmed();
    if (s.startsWith(QLatin1String("0x"), Qt::CaseInsensitive))
        s = s.mid(2);
    bool ok = false;
    quint64 v = s.toULongLong(&ok, 16);
    if (!ok) return raw;
    return QStringLiteral("0x") + QString::number(v, 16).toUpper().rightJustified(16, QLatin1Char('0'));
}

inline quint64 parseAddr(const QString& s)
{
    QString t = s.trimmed();
    if (t.startsWith(QLatin1String("0x"), Qt::CaseInsensitive))
        t = t.mid(2);
    bool ok = false;
    quint64 v = t.toULongLong(&ok, 16);
    return ok ? v : 0ULL;
}

inline QString spacedHex(const QString& hex)
{
    QString stripped = hex.simplified().replace(QLatin1Char(' '), QString());
    QString up = stripped.toUpper();
    QString out;
    out.reserve(up.size() + up.size() / 2);
    for (int i = 0; i < up.size(); i += 2) {
        if (i > 0) out += QLatin1Char(' ');
        out += up.mid(i, 2);
    }
    return out;
}

// -------------------------------------------------------------------
// Log severity
// -------------------------------------------------------------------

enum class LogKind { Info, Ok, Warn, Error, Cmd, Event };

// -------------------------------------------------------------------
