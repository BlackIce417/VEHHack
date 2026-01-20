# 中文文档
中文请参考https://blog.csdn.net/lec2022/article/details/157062663或https://bbs.kanxue.com/thread-289786-1.htm
一种基于VEH硬件断点的Ldr劫持技术，通过在NtOpenSection和NtMapViewOfSection处下断点，转跳到VEH异常处理函数，劫持LoadLibrary。
本项目仅用于思路验证

# Manual PE Loader with Custom GetProcAddress

## Overview

This project demonstrates a **manual PE loader** implemented in C++ on Windows.
It loads a DLL payload into memory **without using the normal loader path**, and resolves required APIs using a **custom implementation of GetProcAddress**.

The loader maps a legitimate system DLL section into memory, replaces its content with a payload DLL, fixes relocations, sets correct memory protections, and finally transfers execution to the payload entry point.

This project is intended for **educational and research purposes**.

---

## Key Features

- Custom implementation of `GetProcAddress`
- Manual PE parsing (DOS / NT / Section / Export tables)
- Forwarded export resolution
- Manual relocation fixing (`IMAGE_BASE_RELOCATION`)
- Manual section mapping and memory protection setup
- Section mapping via `NtCreateSection` / `NtMapViewOfSection`
- Hardware breakpoint + VEH-based syscall interception
- Execution transfer via payload entry point

---

## Technical Details

### Custom API Resolution

- APIs from `ntdll.dll` are resolved using a self-implemented `MyGetProcAddress`
- Supports:
  - Name-based exports
  - Ordinal-based exports
  - Forwarded exports

### PE Loading Process

1. Read payload DLL from disk
2. Create an image section from a legitimate system DLL
3. Map the section into the current process
4. Clear mapped memory
5. Copy payload headers and sections
6. Fix relocations based on new image base
7. Apply proper memory protections per section
8. Jump to payload entry point

### Low-level Techniques Used

- Native API usage (`NtOpenSection`, `NtCreateSection`, `NtMapViewOfSection`, `NtContinue`)
- VEH (Vectored Exception Handling)
- Hardware breakpoints (DR0 / DR7)
- Context manipulation (`CONTEXT` structure)

---

## Build Environment

- Windows x64
- Visual Studio 2026
- C++ (MSVC)
- Target architecture: x64

---

## Usage

1. Place `Payload.dll` in the same directory as the loader executable
2. Build the project in **Debug x64**
3. Run the loader executable
4. The payload DLL entry point will be executed in memory

---

## Notes

- This project avoids calling `LoadLibrary` on the payload DLL
- All PE loading logic is handled manually
- Code is designed for research, reverse engineering, and learning Windows internals

---

## Disclaimer

This project is for **educational and research purposes only**.
The author is not responsible for any misuse of this code.
