#include "mainwindow.h"

void MainWindow::startDaemon()
{
    if (!rpcSocket) {
        rpcSocket = new QTcpSocket(this);
    }

    // Check if daemon is already running by attempting to connect
    bool alreadyRunning = false;
    if (rpcSocket->state() == QAbstractSocket::ConnectedState) {
        alreadyRunning = true;
    } else {
        rpcSocket->abort();
        rpcSocket->connectToHost(QStringLiteral("127.0.0.1"), 31337);
        if (rpcSocket->waitForConnected(100)) {
            alreadyRunning = true;
        }
    }

    if (!alreadyRunning) {
        if (!daemon) {
            daemon = new QProcess(this);
        }

        if (daemon->state() == QProcess::NotRunning) {
            QString exePath = QApplication::applicationDirPath()
                              + QStringLiteral("/hywdbg-core-daemon.exe");
            if (!QFileInfo::exists(exePath))
                exePath = QApplication::applicationDirPath()
                          + QStringLiteral("/../hywdbg-core-daemon.exe");

            daemon->setProgram(exePath);
            daemon->setArguments({});
            daemon->start();

            if (!daemon->waitForStarted(3000)) {
                log(QStringLiteral("Failed to start daemon: ") + daemon->errorString(), LogKind::Error);
                return;
            }

            log(QStringLiteral("Daemon started: ") + exePath, LogKind::Ok);
        }
    }

    if (rpcSocket->state() != QAbstractSocket::ConnectedState) {
        bool connected = false;
        for (int i = 0; i < 20; ++i) {
            rpcSocket->abort();
            rpcSocket->connectToHost(QStringLiteral("127.0.0.1"), 31337);
            if (rpcSocket->waitForConnected(150)) {
                connected = true;
                break;
            }
        }
        if (!connected) {
            log(QStringLiteral("Failed to connect to daemon TCP port 31337"), LogKind::Error);
            return;
        }
        log(QStringLiteral("Connected to daemon at 127.0.0.1:31337"), LogKind::Ok);
    }

    try {
        QJsonObject statusRes = rpc(QStringLiteral("core.backendStatus"), {}).toObject();
        bool active = statusRes.value(QStringLiteral("active")).toBool();
        QString activeKind = statusRes.value(QStringLiteral("kind")).toString();

        if (active && activeKind != selectedBackendKind) {
            log(QStringLiteral("Stopping active backend: ") + activeKind, LogKind::Info);
            rpc(QStringLiteral("core.stopBackend"), {});
            active = false;
        }

        if (!active) {
            log(QStringLiteral("Starting backend: ") + selectedBackendKind, LogKind::Info);
            QJsonObject startParams;
            startParams[QStringLiteral("kind")] = selectedBackendKind;
            QJsonObject startRes = rpc(QStringLiteral("core.startBackend"), startParams).toObject();
            if (!startRes.value(QStringLiteral("started")).toBool()) {
                throw std::runtime_error("Failed to start backend");
            }
        }

        QJsonObject res = rpc(QStringLiteral("dbg.hello"), {}).toObject();
        QString name = res.value(QStringLiteral("name")).toString();
        QString ver  = res.value(QStringLiteral("version")).toString();
        log(QStringLiteral("Backend ready: ") + name + QStringLiteral(" ") + ver, LogKind::Ok);
        setStatus(QStringLiteral("Backend: ") + name);
        // Feature 4: update backendLabel
        if (backendLabel)
            backendLabel->setText(QStringLiteral("Backend: ") + name);
    } catch (const std::exception& e) {
        log(QStringLiteral("Backend initialization failed: ") + QString::fromUtf8(e.what()), LogKind::Error);
    }
}

void MainWindow::shutdownDaemon()
{
    if (rpcSocket && rpcSocket->state() == QAbstractSocket::ConnectedState) {
        try { rpc(QStringLiteral("core.stopBackend"), {}); } catch (...) {}
    }
    if (rpcSocket) {
        rpcSocket->disconnectFromHost();
        rpcSocket->deleteLater();
        rpcSocket = nullptr;
    }
    if (daemon) {
        daemon->terminate();
        daemon->waitForFinished(2000);
    }
}

QJsonValue MainWindow::rpc(const QString& method, const QJsonObject& params)
{
    if (!rpcSocket || rpcSocket->state() != QAbstractSocket::ConnectedState)
        throw std::runtime_error("Not connected to daemon");

    QJsonObject req;
    req[QStringLiteral("jsonrpc")] = QStringLiteral("2.0");
    req[QStringLiteral("id")]      = rpcId++;
    req[QStringLiteral("method")]  = method;
    req[QStringLiteral("params")]  = params;

    QByteArray line = QJsonDocument(req).toJson(QJsonDocument::Compact) + '\n';
    rpcSocket->write(line);
    rpcSocket->waitForBytesWritten(2000);

    QByteArray response;
    while (true) {
        if (!rpcSocket->waitForReadyRead(5000))
            throw std::runtime_error("RPC timeout");
        response += rpcSocket->readLine();
        if (response.endsWith('\n')) break;
    }

    QJsonParseError pe;
    QJsonDocument doc = QJsonDocument::fromJson(response.trimmed(), &pe);
    if (pe.error != QJsonParseError::NoError)
        throw std::runtime_error(("JSON parse error: " + pe.errorString()).toStdString());

    QJsonObject obj = doc.object();
    if (obj.contains(QStringLiteral("error"))) {
        QJsonObject err = obj[QStringLiteral("error")].toObject();
        QString msg = err[QStringLiteral("message")].toString(QStringLiteral("RPC error"));
        throw std::runtime_error(msg.toStdString());
    }
    return obj[QStringLiteral("result")];
}

