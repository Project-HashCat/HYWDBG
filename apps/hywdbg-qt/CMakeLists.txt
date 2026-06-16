cmake_minimum_required(VERSION 3.20)
project(hywdbg_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC OFF)
set(CMAKE_AUTOUIC OFF)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)
qt_standard_project_setup()

qt_add_executable(hywdbg-qt
    src/main.cpp
    src/mainwindow.cpp
    src/rpc.cpp
    src/disasm.cpp
    src/registers.cpp
    src/memory.cpp
    src/debugger.cpp
    src/commands.cpp
    src/dialogs.cpp
    src/userdata.cpp
)

target_link_libraries(hywdbg-qt PRIVATE Qt6::Widgets Qt6::Network)

if (MSVC)
    target_compile_options(hywdbg-qt PRIVATE /W4 /permissive-)
endif()
