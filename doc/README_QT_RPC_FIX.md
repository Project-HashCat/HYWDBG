# HYWDbg Qt RPC build fix

Fixes MSVC errors around `QNetworkRequest` / `QNetworkAccessManager::post` in `apps/hywdbg-qt/src/main.cpp`.

Root cause: `QNetworkRequest req(QUrl(RPC_URL));` can be parsed by MSVC as a function declaration. The patch uses brace initialization and an explicit `QByteArray` payload.

Changed:

```cpp
QNetworkRequest req{QUrl(QString::fromUtf8(RPC_URL))};
req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
const QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
auto* reply = net.post(req, payload);
```
