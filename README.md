# Code Flow Analyzer (CFA) v6 - Smart AOB Edition

![CFA Preview](https://raw.githubusercontent.com/gamesapeca/code-flow-analyzer-v6/main/preview.png)

A high-performance, dynamic memory analyzer designed for advanced reverse engineering and exploit development. CFA v6 integrates the **Capstone Engine** to provide semantic understanding of x86/x64 execution flows directly from volatile memory.

## 🔥 Key Features

- **Smart AOB Generation**: Unlike traditional heuristic maskers, CFA parses raw bytes through Capstone (`Cs.detail = True`). It intelligently masks only dynamic operands (like displacements and immediates) while keeping opcodes and static registers fixed, creating highly resilient signatures (Array of Bytes).
- **Dynamic ASLR Bypass**: Automatically resolves module base addresses at runtime using `ctypes` and PEB structures, adapting to ASLR without manual offsets.
- **Extreme Speed**: Uses optimized Regular Expressions (Regex) for the initial rapid memory sweep, only invoking the heavy disassembler engine when a logical branch (e.g., `TEST`, `CMP`) is validated.
- **SeDebugPrivilege Escalation**: Implements raw Windows API calls to elevate privileges autonomously, allowing analysis of protected processes.
- **Signature Chaining**: Groups multiple contiguous instructions to generate unique sequences, drastically reducing false positives in massive binaries.

## 🛠️ Architecture

*   **Language**: Python 3
*   **Target Arch**: x86_64
*   **Core Dependencies**: `capstone`, `ctypes`, `re`
*   **OS**: Windows Only (Heavy reliance on WinAPI: `OpenProcess`, `ReadProcessMemory`, `VirtualQueryEx`)

## 🚀 Installation & Usage

1. Clone the repository and install Capstone:
   ```bash
   git clone https://github.com/gamesapeca/code-flow-analyzer-v6.git
   cd code-flow-analyzer-v6
   pip install capstone
   ```

2. Run against a target process (requires Administrator privileges):
   ```bash
   python cfa.py --target "TargetProcess.exe" --verbose
   ```

## 🧠 Why Capstone?

Previous versions relied on heuristic byte masking which often led to brittle signatures that broke after minor compiler updates. By integrating Capstone, CFA v6 understands the *meaning* of the instruction. It knows that in `48 8B 05 3F 2A 00 00` (mov rax, qword ptr [rip + 0x2a3f]), the `3F 2A 00 00` is a disposable offset, generating the robust signature: `48 8B 05 ? ? ? ?`.

## ⚠️ Disclaimer
This tool is built for **educational purposes, forensic analysis, and authorized security research**. The author is not responsible for any misuse.

---
*Built for the pursuit of absolute binary truth.*
