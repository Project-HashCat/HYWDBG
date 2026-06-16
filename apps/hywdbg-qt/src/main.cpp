#include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QPushButton>

#ifdef _WIN32
#include <windows.h>
#include <string>
typedef MCIERROR (WINAPI *mciSendStringA_t)(LPCSTR, LPSTR, UINT, HWND);

LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    HMODULE hWinMM = LoadLibraryA("winmm.dll");
    if (hWinMM) {
        mciSendStringA_t p_mciSendStringA = (mciSendStringA_t)GetProcAddress(hWinMM, "mciSendStringA");
        if (p_mciSendStringA) {
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string path(exePath);
            size_t pos = path.find_last_of("\\/");
            if (pos != std::string::npos) {
                path = path.substr(0, pos) + "\\themes\\error.mp3";
            } else {
                path = "themes\\error.mp3";
            }
            std::string cmd = "play \"" + path + "\"";
            p_mciSendStringA(cmd.c_str(), NULL, 0, NULL);
        }
    }
    
    char details[256];
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord) {
        snprintf(details, sizeof(details), "Exception Code: 0x%08X\nException Address: 0x%p",
            (unsigned int)ExceptionInfo->ExceptionRecord->ExceptionCode,
            ExceptionInfo->ExceptionRecord->ExceptionAddress);
    } else {
        snprintf(details, sizeof(details), "Exception details unavailable");
    }

    QMessageBox msgBox;
    msgBox.setWindowTitle(QStringLiteral("You are kidding me"));
    msgBox.setText(QStringLiteral("What Do You Mean the HYWDbg Crashed.\n\n") + QString::fromLocal8Bit(details));
    msgBox.setIcon(QMessageBox::Critical);
    
    msgBox.addButton(QString::fromUtf8("🎵Just Let it Crash 🎵"), QMessageBox::ActionRole);
    msgBox.addButton(QString::fromUtf8("use Hywdbg dbg hywdbg"), QMessageBox::ActionRole);
    msgBox.addButton(QString::fromUtf8("use JIT DBG"), QMessageBox::ActionRole);
    
    msgBox.exec();
    
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetUnhandledExceptionFilter(CrashHandler);
#endif

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("HYWDbg"));
    app.setFont(QFont(QStringLiteral("Consolas"), 11));

    MainWindow w;
    w.show();

    return app.exec();
}
