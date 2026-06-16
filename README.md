# HYWDbg

HYWDbg 是一款现代化、模块化、跨平台的调试器前端，具有强大的多后端架构。它的用户界面 (UI) 基于 **Qt 6 (C++)** 开发，深度致敬并汲取了经典的 x64dbg 操作体验。而它底层的调试后端则全部采用 **Rust** 编写，以确保极致的性能、内存安全性和跨平台兼容性。

## 🚀 架构设计

整个项目主要划分为两个核心部分：
1. **前端 (Qt 6)**：一个轻量且响应迅速的 UI 界面 (`hywdbg-qt`)，负责反汇编视图、内存查看、断点管理以及线程/模块状态的可视化。
2. **后端 (Rust)**：独立的守护进程 (Daemon)，负责直接与操作系统的底层调试 API 进行交互。

前端与后端之间通过标准的 I/O (stdin/stdout) 进行通信，使用自定义的 **JSON-RPC** 协议。

### 内置调试后端
- `titan-backend`：强大的模拟/拦截后端，专为在 Windows x64 下模拟 TitanEngine 的行为而设计，支持模拟 TLS 回调和入口点断点。
- `winapi-backend`：原生 Windows 调试后端，直接调用标准的 Win32 调试 API（如 `CreateProcess`、`WaitForDebugEvent` 等）。
- `dbgeng-backend`：对接微软 DbgEng 引擎 (WinDbg) 的后端。
- `lldb-backend`：对接 LLDB 的后端，主要用于 macOS/Linux 平台的调试。
- `gdbremote-backend`：支持连接到远程 GDB Stub（例如嵌入式设备、QEMU 等）。
- `frida-backend`：基于 Frida 驱动的动态插桩后端。

## 🛠️ 构建与编译

### 环境准备
- **Rust 工具链**：支持 `stable-x86_64-pc-windows-msvc` (64位) 和 `stable-i686-pc-windows-msvc` (32位)。
- **Qt 6.x MSVC**：请确保设置了 `QT_ROOT` 环境变量（例如：`C:\Qt\6.11.1\msvc2022_64` 或对应的 32 位目录）。
- **CMake**：用于配置和构建 Qt 前端应用程序。

### Windows 一键打包
我们提供了一个完善的 PowerShell 部署脚本，可以一键编译整个工作空间（Rust 后端 + Qt UI），并将其干净地打包到一个便携式文件夹中。支持一键构建 64位 和 32位 双版本！

```powershell
# 构建 64 位发行版 (默认)
.\build-dist.ps1 -Config Release -Clean

# 构建 32 位发行版
.\build-dist.ps1 -Config Release -Clean -RustToolchain stable-i686-pc-windows-msvc -RustTarget i686-pc-windows-msvc
```

构建完成后，独立的便携包会生成在 `dist/HYWDbg-Release-x64/` (或 `x86/`) 目录下。

## 📜 许可证 (License)
本项目基于 [Project-HashCat-LICENSE](./LICENSE) 开源许可协议发布。详情请参阅根目录下的 `LICENSE` 文件。
