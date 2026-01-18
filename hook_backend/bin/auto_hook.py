import ctypes, os, sys, time, threading, psutil
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, Toplevel
from ctypes import wintypes

# --- Core WinAPI (Simplified) ---
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

def _def(f, r, *a): f.restype, f.argtypes = r, a
_def(k32.OpenProcess, wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_def(k32.VirtualAllocEx, wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
_def(k32.WriteProcessMemory, wintypes.BOOL, wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_def(k32.CreateRemoteThread, wintypes.HANDLE, wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
_def(k32.GetModuleHandleW, wintypes.HMODULE, wintypes.LPCWSTR)
_def(k32.GetProcAddress, wintypes.LPVOID, wintypes.HMODULE, wintypes.LPCSTR)
_def(k32.CloseHandle, wintypes.BOOL, wintypes.HANDLE)
_def(k32.IsWow64Process, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))

class LiteInjector:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Hook Injector")
        self.root.geometry("700x600")
        
        self.ninja_on, self.processed = False, set()
        self.hook_var = tk.StringVar(value=self._path("__hook__.py"))
        self.dll_var = tk.StringVar(value=self._path("hook64.dll"))
        self.hide_std = tk.BooleanVar(value=True)

        self._build_ui()
        self.refresh()

    def _path(self, name):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        return p if os.path.exists(p) else name

    def _build_ui(self):
        # 1. Top Bar: Search & Filter
        top = tk.Frame(self.root, pady=5)
        top.pack(fill=tk.X, padx=10)
        tk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.LEFT)
        self.search = tk.Entry(top)
        self.search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.search.bind("<KeyRelease>", lambda e: self.update_view())
        tk.Checkbutton(top, text="Ignore Std Installs", variable=self.hide_std, command=self.update_view).pack(side=tk.RIGHT)

        # 2. Process Tree
        cols = ("PID", "Name", "Arch", "Path")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=12)
        for c, w in zip(cols, (60, 150, 60, 400)): 
            self.tree.heading(c, text=c); self.tree.column(c, width=w)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)
        self.tree.bind("<Double-1>", lambda e: self.run_inject())

        # 3. Settings
        cfg = tk.LabelFrame(self.root, text="Configuration", padx=10, pady=5)
        cfg.pack(fill=tk.X, padx=10, pady=10)
        
        # Hook Path - Now Wide and Visible
        h_row = tk.Frame(cfg)
        h_row.pack(fill=tk.X, pady=2)
        tk.Label(h_row, text="Hook:").pack(side=tk.LEFT)
        tk.Entry(h_row, textvariable=self.hook_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(h_row, text="Edit", command=self.edit_hook).pack(side=tk.RIGHT)
        tk.Button(h_row, text="...", command=lambda: self.hook_var.set(filedialog.askopenfilename() or self.hook_var.get())).pack(side=tk.RIGHT, padx=2)

        # DLL Path
        d_row = tk.Frame(cfg)
        d_row.pack(fill=tk.X, pady=2)
        tk.Label(d_row, text="DLL:  ").pack(side=tk.LEFT)
        tk.Entry(d_row, textvariable=self.dll_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Action Buttons
        btns = tk.Frame(self.root, pady=5)
        btns.pack(fill=tk.X, padx=10)
        self.btn_ninja = tk.Button(btns, text="Ninja Mode: OFF", command=self.toggle_ninja, width=15)
        self.btn_ninja.pack(side=tk.LEFT)
        tk.Button(btns, text="INJECT SELECTED", bg="#d32f2f", fg="white", font=("Arial", 9, "bold"), command=self.run_inject).pack(side=tk.RIGHT)

        self.log_box = scrolledtext.ScrolledText(self.root, height=4, state='disabled', bg="#1e1e1e", fg="#00ff00", font=("Consolas", 8))
        self.log_box.pack(fill=tk.X, padx=10, pady=5)

    def log(self, m):
        self.log_box.config(state='normal'); self.log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {m}\n"); self.log_box.see(tk.END); self.log_box.config(state='disabled')

    def is_target(self, p):
        """ Checks ONLY for python3*.dll and ignores standard installation paths. """
        try:
            exe = (p.info['exe'] or "").lower()
            if self.hide_std.get():
                if any(x in exe for x in ["program files", "windows", "appdata\\local\\programs\\python"]):
                    return False
            
            # THE CORE CHECK: Scan loaded modules for python3*.dll
            for m in p.memory_maps():
                if "python3" in os.path.basename(m.path).lower():
                    return True
        except: pass
        return False

    def refresh(self):
        self.procs = [p for p in psutil.process_iter(['pid', 'name', 'exe'])]
        self.update_view()

    def update_view(self):
        self.tree.delete(*self.tree.get_children())
        query = self.search.get().lower()
        for p in self.procs:
            if self.is_target(p):
                pid, name, exe = p.info['pid'], p.info['name'], p.info['exe'] or ""
                if query in name.lower() or query in str(pid):
                    arch = self.get_arch(pid)
                    self.tree.insert("", tk.END, values=(pid, name, "x64" if arch else "x86", exe))

    def get_arch(self, pid):
        try:
            h = k32.OpenProcess(0x1000, False, pid)
            if h:
                wow = wintypes.BOOL()
                k32.IsWow64Process(h, ctypes.byref(wow))
                k32.CloseHandle(h)
                return not wow.value
        except: pass
        return True

    def run_inject(self):
        sel = self.tree.selection()
        if sel:
            pid, name = self.tree.item(sel[0])['values'][:2]
            threading.Thread(target=self.inject, args=(int(pid), name), daemon=True).start()

    def inject(self, pid, name):
        try:
            self.log(f"Targeting: {name} ({pid})")
            is64, dll = self.get_arch(pid), self.dll_var.get()
            
            # Auto-Bitness
            if is64 and "32" in dll: dll = dll.replace("32", "64")
            elif not is64 and "64" in dll: dll = dll.replace("64", "32")
            
            if not os.path.exists(dll): return self.log("Error: DLL not found")

            # Setup Hook Config
            cfg_path = os.path.join(os.getenv('TEMP'), "hook_config.ini")
            with open(cfg_path, "w") as f:
                f.write(f"[General]\nHookPath={os.path.dirname(os.path.abspath(self.hook_var.get()))}\n")

            # Native LoadLibrary Injection
            h_proc = k32.OpenProcess(0x1F0FFF, False, pid)
            if not h_proc: return self.log("Failed to open process")

            path = os.path.abspath(dll).encode('utf-16le') + b'\0'
            mem = k32.VirtualAllocEx(h_proc, 0, len(path), 0x1000, 0x04)
            k32.WriteProcessMemory(h_proc, mem, path, len(path), 0)
            
            load_lib = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
            h_thread = k32.CreateRemoteThread(h_proc, None, 0, load_lib, mem, 0, None)
            
            if not h_thread: # Fallback for modern Windows
                h_t = wintypes.HANDLE()
                ntdll.NtCreateThreadEx(ctypes.byref(h_t), 0x1FFFFF, None, h_proc, load_lib, mem, 0, 0, 0, 0, None)
                h_thread = h_t.value

            if h_thread:
                self.log(f"Successfully Injected into {name}!")
                k32.CloseHandle(h_thread)
            k32.CloseHandle(h_proc)
        except Exception as e: self.log(f"Err: {e}")

    def toggle_ninja(self):
        self.ninja_on = not self.ninja_on
        self.btn_ninja.config(text="Ninja: ON" if self.ninja_on else "Ninja: OFF", bg="green" if self.ninja_on else "SystemButtonFace")
        if self.ninja_on: threading.Thread(target=self.ninja_loop, daemon=True).start()

    def ninja_loop(self):
        while self.ninja_on:
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                if p.pid not in self.processed and p.pid != os.getpid() and self.is_target(p):
                    self.processed.add(p.pid)
                    self.inject(p.pid, p.name())
            time.sleep(2)

    def edit_hook(self):
        top = Toplevel(self.root); top.title("Editor"); top.geometry("500x400")
        txt = scrolledtext.ScrolledText(top, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True)
        try:
            with open(self.hook_var.get(), 'r') as f: txt.insert('1.0', f.read())
        except: pass
        tk.Button(top, text="Save", bg="green", fg="white", command=lambda: [open(self.hook_var.get(), 'w').write(txt.get('1.0', tk.END)), messagebox.showinfo("Saved", "Hook updated")]).pack(fill=tk.X)

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    root = tk.Tk(); LiteInjector(root); root.mainloop()