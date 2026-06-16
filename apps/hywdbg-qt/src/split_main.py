import re
import os

with open('main.cpp', 'r') as f:
    lines = f.readlines()

def get_block(start_marker, end_marker=None):
    res = []
    in_block = False
    for i, line in enumerate(lines):
        if start_marker in line:
            in_block = True
        if in_block:
            res.append(line)
        if in_block and end_marker and end_marker in line:
            break
    return "".join(res)

global_h = """#pragma once
"""
for line in lines:
    if line.startswith("#include"):
        if "main.moc" not in line and "mainwindow.moc" not in line:
            global_h += line
global_h += "\n"

# Helpers
in_helpers = False
for line in lines:
    if "// Free helper functions" in line:
        in_helpers = True
    if "// MainWindow" in line:
        in_helpers = False
    if in_helpers:
        # replace static with inline
        if line.startswith("static QString") or line.startswith("static quint64"):
            line = line.replace("static ", "inline ")
        global_h += line

with open('global.h', 'w') as f:
    f.write(global_h)

mainwindow_h = """#pragma once
#include "global.h"

"""
in_class = False
for line in lines:
    if "class MainWindow" in line:
        in_class = True
    if in_class:
        mainwindow_h += line
    if in_class and "};" in line:
        break

with open('mainwindow.h', 'w') as f:
    f.write(mainwindow_h)

def extract_funcs(names, includes="#include \"mainwindow.h\"\n\n"):
    out = includes
    for name in names:
        in_func = False
        brace_count = 0
        for line in lines:
            if re.match(r'^[\w\s\*<>:]+\s+MainWindow::' + name + r'\(', line) or re.match(r'^[\w\s\*<>:]+\s+MainWindow::~' + name + r'\(', line):
                in_func = True
                
            if in_func:
                out += line
                if '{' in line:
                    brace_count += line.count('{')
                if '}' in line:
                    brace_count -= line.count('}')
                    if brace_count == 0:
                        in_func = False
                        out += "\n"
    return out

with open('mainwindow.cpp', 'w') as f:
    content = extract_funcs(['MainWindow', '~MainWindow', 'applyDarkTheme', 'buildMenu', 'buildToolBar', 'buildCentralWidget', 'buildDocks', 'makeTable', 'makeDock', 'tableItem', 'setStatus', 'eventFilter'])
    content += "\n#include \"mainwindow.moc\"\n"
    f.write(content)

with open('rpc.cpp', 'w') as f:
    f.write(extract_funcs(['startDaemon', 'shutdownDaemon', 'rpc']))

with open('disasm.cpp', 'w') as f:
    f.write(extract_funcs(['mnemonicCategory', 'mnemonicColor', 'addDisasmRow', 'updateDisasmRowHighlight', 'resolveToAddr', 'refreshDisasm', 'appendDisasm']))

with open('registers.cpp', 'w') as f:
    f.write(extract_funcs(['refreshRegs']))

with open('memory.cpp', 'w') as f:
    f.write(extract_funcs(['refreshMem', 'refreshStack', 'nopOutAt']))

with open('debugger.cpp', 'w') as f:
    f.write(extract_funcs(['log', 'refreshModules', 'refreshThreads', 'refreshCallStack', 'refreshBpList', 'refreshAll', 'toggleBpAt', 'runToAddr', 'formatEventDetail']))

with open('commands.cpp', 'w') as f:
    f.write(extract_funcs(['runCommand']))

with open('dialogs.cpp', 'w') as f:
    f.write(extract_funcs(['showAttachDialog']))

with open('main.cpp', 'w') as f:
    f.write("""#include "mainwindow.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("HYWDbg"));
    app.setFont(QFont(QStringLiteral("Consolas"), 11));

    MainWindow w;
    w.show();

    return app.exec();
}
""")

print("Split completed successfully!")
