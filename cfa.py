"""
Code Flow Analyzer v6 - Capstone-Aware Smart AOB
Ultimate precision signature generation for obfuscated binaries.

Modules:
- Smart-AOB: Uses Capstone's detailed instruction parsing to mask only dynamic bytes.
- Hybrid Scan: Regex speed + Capstone precision.
- Sentinel: Remote JSON reporting via Webhooks.
"""

import ctypes
import ctypes.wintypes
import struct
import os
import sys
import re
import json
import argparse
import requests

try:
    import capstone
except ImportError:
    print("[!] Error: 'capstone' library is mandatory for v6. Run: pip install capstone")
    sys.exit(1)

# --- Windows API Definitions ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

# --- Patterns (Regex) ---
PATTERNS = {
    'x86': [(re.compile(b'\x85[\xC0-\xFF]'), "TEST REG, REG"), (re.compile(b'\x83[\x78-\x7F].\x00'), "CMP [REG+OFF8], 0")],
    'x64': [(re.compile(b'[\x48-\x4F]\x85[\xC0-\xFF]'), "TEST REG64, REG64"), (re.compile(b'[\x48-\x4F]\x83[\x78-\x7F].\x00'), "CMP [REG64+OFF8], 0")]
}

def enable_debug_privilege():
    hToken = ctypes.wintypes.HANDLE()
    if not ctypes.windll.advapi32.OpenProcessToken(ctypes.windll.kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        return False
    luid = LUID()
    if not ctypes.windll.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ctypes.windll.advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    return True

class SmartAnalyzer:
    def __init__(self, target, webhook=None):
        self.target = target
        self.webhook = webhook
        self.pid = self._resolve_pid()
        self.is_64bit = False
        self.base = None
        self.size = None
        self.h_proc = None
        self.md = None

    def _resolve_pid(self):
        if self.target.isdigit(): return int(self.target)
        out = os.popen('tasklist /NH').read()
        for line in out.splitlines():
            if self.target.lower() in line.lower(): return int(line.split()[1])
        return None

    def attach(self):
        if not self.pid: return False
        enable_debug_privilege()
        self.h_proc = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not self.h_proc: return False
        is_wow64 = ctypes.c_bool(False)
        ctypes.windll.kernel32.IsWow64Process(self.h_proc, ctypes.byref(is_wow64))
        self.is_64bit = not is_wow64.value if struct.calcsize("P") == 8 else False
        
        # Initialize Capstone with Details enabled
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.is_64bit else capstone.CS_MODE_32)
        self.md.detail = True
        
        h_mods = (ctypes.wintypes.HMODULE * 1024)()
        needed = ctypes.c_ulong()
        if ctypes.windll.psapi.EnumProcessModules(self.h_proc, h_mods, ctypes.sizeof(h_mods), ctypes.byref(needed)):
            mi = type('MODULEINFO', (ctypes.Structure,), {'_fields_': [('lpBaseOfDll', ctypes.c_void_p), ('SizeOfImage', ctypes.c_uint32), ('EntryPoint', ctypes.c_void_p)]})()
            ctypes.windll.psapi.GetModuleInformation(self.h_proc, h_mods[0], ctypes.byref(mi), ctypes.sizeof(mi))
            self.base = mi.lpBaseOfDll
            self.size = mi.SizeOfImage
            return True
        return False

    def generate_smart_aob(self, addr, data_chunk):
        """Uses Capstone to precisely mask operands while keeping opcodes intact."""
        aob_parts = []
        insns = list(self.md.disasm(data_chunk, addr))
        
        # We process the first 2-3 instructions to create a stable signature chain
        max_chain = 2 
        for i, insn in enumerate(insns):
            if i >= max_chain: break
            
            # Start with raw bytes
            masked_bytes = list(insn.bytes)
            
            # Mask Displacement if present
            if insn.disp_offset != 0:
                for j in range(insn.disp_size):
                    masked_bytes[insn.disp_offset + j] = None
            
            # Mask Immediates if present
            if insn.imm_offset != 0:
                for j in range(insn.imm_size):
                    masked_bytes[insn.imm_offset + j] = None

            # Convert to string parts
            for b in masked_bytes:
                if b is None:
                    aob_parts.append("??")
                else:
                    aob_parts.append(f"{b:02X}")
                    
        return " ".join(aob_parts)

    def scan(self):
        data = ctypes.create_string_buffer(self.size)
        read = ctypes.c_size_t(0)
        ctypes.windll.kernel32.ReadProcessMemory(self.h_proc, ctypes.c_void_p(self.base), data, self.size, ctypes.byref(read))
        memory = data.raw
        
        findings = []
        arch = 'x64' if self.is_64bit else 'x86'
        
        for regex, desc in PATTERNS[arch]:
            for m in regex.finditer(memory):
                pos = m.end()
                va_instr = self.base + m.start()
                if pos + 6 < len(memory):
                    # Find branch logic
                    target = None
                    if memory[pos] == 0x74: # JZ Short
                        off = struct.unpack('b', bytes([memory[pos+1]]))[0]
                        target = self.base + pos + 2 + off
                    elif memory[pos] == 0x0F and memory[pos+1] == 0x84: # JZ Near
                        off = struct.unpack('<i', memory[pos+2:pos+6])[0]
                        target = self.base + pos + 6 + off
                    
                    if target:
                        # Generate detailed report
                        insns = list(self.md.disasm(memory[m.start():m.start()+20], va_instr))
                        asm = f"{insns[0].mnemonic} {insns[0].op_str}" if insns else "Unknown"
                        
                        findings.append({
                            "address": f"0x{va_instr:X}",
                            "assembly": asm,
                            "target": f"0x{target:X}",
                            "aob": self.generate_smart_aob(va_instr, memory[m.start():m.start()+15])
                        })
        return findings

    def report(self, results):
        print(f"\n{'ADDRESS':<14} {'ASSEMBLY (Capstone)':<28} {'TARGET':<14} {'STABLE AOB SIGNATURE'}")
        print("-" * 100)
        for r in results:
            print(f"{r['address']:<14} {r['assembly']:<28} {r['target']:<14} {r['aob']}")
        
        if self.webhook:
            try:
                requests.post(self.webhook, json={"payload": results}, timeout=5)
                print("[+] Results exported to Webhook.")
            except:
                print("[-] Webhook failed.")

def main():
    parser = argparse.ArgumentParser(description="Code Flow Analyzer v6 - Smart AOB Edition")
    parser.add_argument("target", help="PID or Image Name")
    parser.add_argument("--webhook", help="Webhook URL")
    args = parser.parse_args()

    analyzer = SmartAnalyzer(args.target, args.webhook)
    if analyzer.attach():
        print(f"[*] Attached to {args.target} (Arch: {'64bit' if analyzer.is_64bit else '32bit'})")
        results = analyzer.scan()
        analyzer.report(results)
    else:
        print("[-] Connection failed.")

if __name__ == "__main__":
    main()
