/**
 * hook_dll.cpp
 * Automatically detects and sets PYTHONHOME based on python.exe location
 * Redirects stdout/stderr to hook_output.log
 *
 * FIXED: Ensures PYTHONHOME is correctly passed to PyRun_SimpleString to fix
 * ModuleNotFoundError for standard library modules like 'concurrent.futures'.
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <direct.h>
#include <shlobj.h>
#include <vector>
#include <algorithm>
#include <string.h> // For strcasecmp and strtok

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

// Global storage for the detected PYTHONHOME path
static char g_pythonHomePath[MAX_PATH] = {0};
#define PYMODULE_NAME "__hook__"

static FILE *g_logFile = NULL;

// ... (dbgPrintf and FindPythonExePath functions remain the same) ...

static void dbgPrintf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  OutputDebugStringA(buf);
}

static void CheckForProtection() {
  if (IsDebuggerPresent()) {
    dbgPrintf("[HOOK] WARNING: Debugger detected!\n");
  }

  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  if (hKernel32) {
    BYTE *pLoadLib = (BYTE *)GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLib && (*pLoadLib == 0xE9 || *pLoadLib == 0xEB)) {
      dbgPrintf("[HOOK] WARNING: LoadLibraryW appears to be hooked (JMP/CALL)!\n");
    }
  }
}

static bool GetHookFilePathFromConfig(char *outPath, size_t maxLen) {
  const char *configPath = "C:\\pythondumps\\hook_config.ini";
  FILE *f = fopen(configPath, "r");
  if (!f) return false;

  char line[MAX_PATH];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "HookPath=", 9) == 0) {
      char *path = line + 9;
      // Trim newline
      char *nl = strpbrk(path, "\r\n");
      if (nl) *nl = '\0';

      if (path[0] != '\0') {
        snprintf(outPath, maxLen, "%s\\%s.py", path, PYMODULE_NAME);
        found = true;
        break;
      }
    }
  }
  fclose(f);
  return found;
}

// Find python.exe in running processes
static bool FindPythonExePath(char *outPath, size_t maxLen) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (Process32First(hSnapshot, &pe32)) {
    do {
      if (strcasecmp(pe32.szExeFile, "python.exe") == 0 ||
          strcasecmp(pe32.szExeFile, "pythonw.exe") == 0) {

        HANDLE hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                        pe32.th32ProcessID);
        if (hProcess) {
          char path[MAX_PATH];
          if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
            strncpy(outPath, path, maxLen - 1);
            outPath[maxLen - 1] = '\0';
            CloseHandle(hProcess);
            CloseHandle(hSnapshot);
            return true;
          }
          CloseHandle(hProcess);
        }
      }
    } while (Process32Next(hSnapshot, &pe32));
  }

  CloseHandle(hSnapshot);
  return false;
}

// ... (IsValidPythonHome and ScanBasePathForPython functions remain the same)
// ...

static bool IsValidPythonHome(const char *dir, char *outPath, size_t maxLen) {
  char libPath[MAX_PATH];
  snprintf(libPath, MAX_PATH, "%s\\Lib", dir);

  DWORD attrib = GetFileAttributesA(libPath);
  if (attrib != INVALID_FILE_ATTRIBUTES &&
      (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
    strncpy(outPath, dir, maxLen - 1);
    outPath[maxLen - 1] = '\0';
    return true;
  }
  return false;
}

static bool ScanBasePathForPython(const char *basePath, char *outPath,
                                  size_t maxLen) {
  char searchPattern[MAX_PATH];
  snprintf(searchPattern, MAX_PATH, "%s\\Python3*", basePath);

  WIN32_FIND_DATAA findData;
  HANDLE hFind = FindFirstFileA(searchPattern, &findData);

  if (hFind == INVALID_HANDLE_VALUE) {
    return false;
  }

  std::vector<std::string> foundHomes;

  do {
    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        strcmp(findData.cFileName, ".") != 0 &&
        strcmp(findData.cFileName, "..") != 0) {

      char testDir[MAX_PATH];
      snprintf(testDir, MAX_PATH, "%s\\%s", basePath, findData.cFileName);

      char tempPath[MAX_PATH];
      if (IsValidPythonHome(testDir, tempPath, MAX_PATH)) {
        foundHomes.push_back(findData.cFileName);
      }
    }
  } while (FindNextFileA(hFind, &findData));

  FindClose(hFind);

  if (foundHomes.empty()) {
    return false;
  }

  std::sort(foundHomes.rbegin(), foundHomes.rend());

  snprintf(outPath, maxLen, "%s\\%s", basePath, foundHomes[0].c_str());
  return true;
}

static bool FindPythonInstallation(char *outPath, size_t maxLen) {
  char basePath[MAX_PATH];

  // 1. Check C:\ (e.g., C:\Python312)
  if (ScanBasePathForPython("C:", outPath, maxLen))
    return true;

  // 2. Check Program Files
  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, basePath))) {
    if (ScanBasePathForPython(basePath, outPath, maxLen))
      return true;
  }

  // 3. Check Program Files (x86)
  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, basePath))) {
    if (ScanBasePathForPython(basePath, outPath, maxLen))
      return true;
  }

  // 4. Check Local AppData
  if (SUCCEEDED(
          SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, basePath))) {
    char localPrograms[MAX_PATH];

    // Check ...\AppData\Local\Programs\Python
    snprintf(localPrograms, MAX_PATH, "%s\\Programs\\Python", basePath);
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;

    // Check ...\AppData\Local\Programs
    snprintf(localPrograms, MAX_PATH, "%s\\Programs", basePath);
    if (ScanBasePathForPython(localPrograms, outPath, maxLen))
      return true;
  }

  return false;
}

// Modified to store the found path in a global variable
static void AutoSetPythonHome() {
  // Check if PYTHONHOME already exists
  char existing[MAX_PATH];
  if (GetEnvironmentVariableA("PYTHONHOME", existing, MAX_PATH) > 0) {
    dbgPrintf("[HOOK] PYTHONHOME already set to: %s\n", existing);
    strncpy(g_pythonHomePath, existing, MAX_PATH - 1);
    g_pythonHomePath[MAX_PATH - 1] = '\0';
    return;
  }

  char pythonHome[MAX_PATH];
  bool found = false;

  // Method 0: Check if WE are the python.exe (Current Process)
  // This is critical for "pure" python injection scenarios.
  char currentExe[MAX_PATH];
  if (GetModuleFileNameA(NULL, currentExe, MAX_PATH)) {
    const char *filename = strrchr(currentExe, '\\');
    if (filename)
      filename++;
    else
      filename = currentExe;

    if (strcasecmp(filename, "python.exe") == 0 ||
        strcasecmp(filename, "pythonw.exe") == 0) {
      strncpy(pythonHome, currentExe, MAX_PATH - 1);
      pythonHome[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(pythonHome);

      // Trust the current exe's directory as HOME
      found = true;
      dbgPrintf("[HOOK] Injected into python.exe, using its dir as HOME: %s\n",
                pythonHome);
    }
  }

  // Method 1: Try to find python.exe from running processes (Fallback)
  if (!found) {
    char pythonExe[MAX_PATH];
    if (FindPythonExePath(pythonExe, MAX_PATH)) {
      // ... (path manipulation logic) ...
      strncpy(pythonHome, pythonExe, MAX_PATH - 1);
      pythonHome[MAX_PATH - 1] = '\0';
      PathRemoveFileSpecA(pythonHome);
      if (IsValidPythonHome(pythonHome, pythonHome, MAX_PATH))
        found = true;
    }
  }

  // Method 2 & 3: Check common installation paths and PATH
  if (!found)
    found = FindPythonInstallation(pythonHome, MAX_PATH);
  if (!found) {
    char pathEnv[32768];
    if (GetEnvironmentVariableA("PATH", pathEnv, sizeof(pathEnv)) > 0) {
      char *token = strtok(pathEnv, ";");
      while (token != NULL) {
        char testExe[MAX_PATH];
        snprintf(testExe, MAX_PATH, "%s\\python.exe", token);

        DWORD attrib = GetFileAttributesA(testExe);
        if (attrib != INVALID_FILE_ATTRIBUTES &&
            !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
          if (IsValidPythonHome(token, pythonHome, MAX_PATH)) {
            found = true;
            break;
          }
        }
        token = strtok(NULL, ";");
      }
    }
  }

  if (found) {
    // Set PYTHONHOME and store globally for hookImpl
    SetEnvironmentVariableA("PYTHONHOME", pythonHome);
    strncpy(g_pythonHomePath, pythonHome, MAX_PATH - 1); // Store path
    g_pythonHomePath[MAX_PATH - 1] = '\0';

    dbgPrintf("[HOOK] Set PYTHONHOME=%s\n", pythonHome);
    if (g_logFile) fprintf(g_logFile, "[HOOK] Set PYTHONHOME=%s\n", pythonHome);

    // Also set PYTHONPATH
    char pythonPath[MAX_PATH * 2];
    snprintf(pythonPath, sizeof(pythonPath), "%s\\Lib;%s\\Lib\\site-packages",
             pythonHome, pythonHome);
    SetEnvironmentVariableA("PYTHONPATH", pythonPath);
    dbgPrintf("[HOOK] Set PYTHONPATH=%s\n", pythonPath);
    if (g_logFile) fprintf(g_logFile, "[HOOK] Set PYTHONPATH=%s\n", pythonPath);
  } else {
    dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
    if (g_logFile) fprintf(g_logFile, "[HOOK] Could not auto-detect PYTHONHOME\n");
  }
}

// ... (SetupStdoutStderrToLog function remains the same) ...

static bool SetupStdoutStderrToLog(char *outLogPath) {
  // Try to use C:\pythondumps for visibility
  char logDir[] = "C:\\pythondumps";
  CreateDirectoryA(logDir, NULL);

  char logPath[MAX_PATH];
  snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", logDir);

  // Fallback to Public/pythondumps if C:\pythondumps fails
  g_logFile = fopen(logPath, "a");
  if (!g_logFile) {
    char publicLogDir[] = "C:\\Users\\Public\\pythondumps";
    CreateDirectoryA(publicLogDir, NULL);
    snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", publicLogDir);
    g_logFile = fopen(logPath, "a");
  }

  if (!g_logFile)
    return false;

  setvbuf(g_logFile, NULL, _IOLBF, 0);
  freopen(logPath, "a", stdout);
  freopen(logPath, "a", stderr);

  if (outLogPath)
    strncpy(outLogPath, logPath, MAX_PATH - 1);

  dbgPrintf("[HOOK] stdout/stderr redirected to %s\n", logPath);
  return true;
}

DWORD WINAPI hookImpl(LPVOID lpParam) {
  // FIRST: Auto-detect and set PYTHONHOME before anything else
  AutoSetPythonHome();

  // Check for common usermode protections/watchdogs
  CheckForProtection();

  // Setup logging
  char logPathBuf[MAX_PATH] = {0};
  SetupStdoutStderrToLog(logPathBuf);

  char dllName[32];
  HMODULE hPyDll = nullptr;

  // 1. Check generic python3.dll
  hPyDll = GetModuleHandleA("python3.dll");
  if (hPyDll) {
    strncpy(dllName, "python3.dll", sizeof(dllName));
    dbgPrintf("[HOOK] Found loaded python3.dll\n");
  } else {
    // 2. Check python3xx.dll down from 3.13 to 3.6
    for (int i = 13; i >= 6; i--) {
      snprintf(dllName, sizeof(dllName), "python3%d.dll", i);
      hPyDll = GetModuleHandleA(dllName);
      if (hPyDll) {
        dbgPrintf("[HOOK] Found loaded %s\n", dllName);
        break;
      }
    }
  }

  if (!hPyDll) {
    MessageBoxA(NULL, "No python3x.dll found", "Hook Error",
                MB_ICONEXCLAMATION);
    return 1;
  }

  typedef void *(*PyImportModuleFunc)(const char *);
  typedef void (*Py_DecRefFunc)(void *);
  typedef int (*PyGILState_EnsureFunc)();
  typedef void (*PyGILState_ReleaseFunc)(int);
  typedef void (*PyErr_PrintFunc)();
  typedef int (*PyRun_SimpleStringFunc)(const char *);

  auto PyImport_ImportModule =
      (PyImportModuleFunc)GetProcAddress(hPyDll, "PyImport_ImportModule");
  auto Py_DecRef = (Py_DecRefFunc)GetProcAddress(hPyDll, "Py_DecRef");
  auto PyGILState_Ensure =
      (PyGILState_EnsureFunc)GetProcAddress(hPyDll, "PyGILState_Ensure");
  auto PyGILState_Release =
      (PyGILState_ReleaseFunc)GetProcAddress(hPyDll, "PyGILState_Release");
  auto PyErr_Print = (PyErr_PrintFunc)GetProcAddress(hPyDll, "PyErr_Print");
  auto PyRun_SimpleString =
      (PyRun_SimpleStringFunc)GetProcAddress(hPyDll, "PyRun_SimpleString");

  if (!PyImport_ImportModule || !PyGILState_Ensure || !PyGILState_Release) {
    MessageBoxA(NULL, "Cannot load Python C-API functions", "Hook Error",
                MB_ICONEXCLAMATION);
    return 1;
  }

  // Acquire GIL
  int gilState = PyGILState_Ensure();

  // Redirect Python's stdout/stderr to our log file and add sys.path entries
  if (PyRun_SimpleString) {
    char pyLogPath[MAX_PATH];
    strncpy(pyLogPath, logPathBuf, sizeof(pyLogPath) - 1);
    pyLogPath[sizeof(pyLogPath) - 1] = '\0';

    // Convert backslashes to forward slashes for Python
    for (char *p = pyLogPath; *p; ++p) {
      if (*p == '\\')
        *p = '/';
    }

    // Prepare the PythonHome path for injection
    char pyHomePath[MAX_PATH];
    strncpy(pyHomePath, g_pythonHomePath, sizeof(pyHomePath) - 1);
    pyHomePath[sizeof(pyHomePath) - 1] = '\0'; // Ensure termination
    for (char *p = pyHomePath; *p; ++p) {
      if (*p == '\\')
        *p = '/';
    }

    // Get Python Version for logging
    typedef const char *(*Py_GetVersionFunc)();
    auto Py_GetVersion = (Py_GetVersionFunc)GetProcAddress(hPyDll, "Py_GetVersion");
    if (Py_GetVersion) {
        dbgPrintf("[HOOK] Python Version: %s\n", Py_GetVersion());
        if (g_logFile) fprintf(g_logFile, "[HOOK] Python Version: %s\n", Py_GetVersion());
    }

    char pycmd[8192];
    snprintf(
        pycmd, sizeof(pycmd),
        "import sys, os\n"
        "try:\n"
        "    f = open(r'%s', 'a', buffering=1, encoding='utf-8')\n"
        "    sys.stdout = f\n"
        "    sys.stderr = f\n"
        "    print('Python stdout/stderr redirected to log')\n"
        "    print('sys.executable:', sys.executable)\n"
        "    print('sys.prefix:', sys.prefix)\n"
        "    print('sys.path:', sys.path)\n"
        "    \n"
        "    # Inject detected path directly into sys.path logic\n"
        "    pythonhome = r'%s'\n"
        "    print('Detected PYTHONHOME (Injected):', pythonhome)\n"
        "    \n"
        "    # FORCE ADD CWD and EXE DIR to sys.path to find __hook__.py\n"
        "    cwd = os.getcwd()\n"
        "    exe_dir = os.path.dirname(sys.executable)\n"
        "    if cwd not in sys.path: sys.path.insert(0, cwd)\n"
        "    if exe_dir not in sys.path: sys.path.insert(0, exe_dir)\n"
        "    print('Forced CWD into sys.path:', cwd)\n"
        "    print('Forced ExeDir into sys.path:', exe_dir)\n"
        "    \n"
        "    # GLOBAL HOOK PATH LOGIC\n"
        "    # 1. Check Env Var\n"
        "    env_hook = os.environ.get('HYDRA_HOOK_PATH')\n"
        "    if env_hook and os.path.exists(env_hook) and env_hook not in "
        "sys.path:\n"
        "        sys.path.insert(0, env_hook)\n"
        "        print('Added Global Env Hook Path:', env_hook)\n"
        "    \n"
        "    # 2. Check Shared Config File\n"
        "    config_path = r'C:\\pythondumps\\hook_config.ini'\n"
        "    if os.path.exists(config_path):\n"
        "        try:\n"
        "            with open(config_path, 'r') as cf:\n"
        "                for line in cf:\n"
        "                    if line.startswith('HookPath='):\n"
        "                        path_val = line.strip().split('=', 1)[1]\n"
        "                        if path_val and os.path.exists(path_val) and "
        "path_val not in sys.path:\n"
        "                            sys.path.insert(0, path_val)\n"
        "                            print('Added Global Config Hook Path:', "
        "path_val)\n"
        "        except Exception as e:\n"
        "            print('Failed to read config:', e)\n"
        "    \n"
        "    if pythonhome and os.path.isdir(pythonhome):\n"
        "        lib = os.path.join(pythonhome, 'Lib')\n"
        "        site_packages = os.path.join(lib, 'site-packages')\n"
        "        if os.path.isdir(lib) and lib not in sys.path:\n"
        "            sys.path.insert(0, lib)\n"
        "            print('Added to sys.path (Lib):', lib)\n"
        "        if os.path.isdir(site_packages) and site_packages not in "
        "sys.path:\n"
        "            sys.path.insert(0, site_packages)\n"
        "            print('Added to sys.path (site-packages):', "
        "site_packages)\n"
        "    \n"
        "    # Test if concurrent.futures is now available\n"
        "    try:\n"
        "        import concurrent.futures\n"
        "        print('SUCCESS: concurrent.futures is available')\n"
        "    except ImportError as e:\n"
        "        print('ERROR: concurrent.futures still not available:', e)\n"
        "        print('Updated sys.path:', sys.path)\n"
        "except Exception as e:\n"
        "    print('Failed to setup:', e)\n",
        pyLogPath,
        pyHomePath); // Pass path string as argument 2 to snprintf

    int res = PyRun_SimpleString(pycmd);
    dbgPrintf("[HOOK] PyRun_SimpleString(setup) returned: %d\n", res);
    if (g_logFile) fprintf(g_logFile, "[HOOK] PyRun_SimpleString(setup) returned: %d\n", res);
    
    if (res != 0) {
      dbgPrintf("[HOOK] Failed to run Python setup snippet\n");
    }
  }

  // ATTEMPT EXPLICIT LOAD IF PyImport_ImportModule fails
  void *hook_module = PyImport_ImportModule(PYMODULE_NAME);

  if (hook_module) {
    Py_DecRef(hook_module);
    PyGILState_Release(gilState);
    dbgPrintf("[HOOK] Successfully imported " PYMODULE_NAME " via standard import\n");
    if (g_logFile) fprintf(g_logFile, "[HOOK] Successfully imported " PYMODULE_NAME " via standard import\n");
    MessageBoxA(NULL, "Hook injection successful!", "Success", MB_OK);
    return 0;
  } else {
    dbgPrintf("[HOOK] Standard import failed, trying explicit file execution...\n");
    if (g_logFile) fprintf(g_logFile, "[HOOK] Standard import failed, trying explicit file execution...\n");

    char hookFilePath[MAX_PATH];
    if (GetHookFilePathFromConfig(hookFilePath, MAX_PATH)) {
      dbgPrintf("[HOOK] Found explicit hook path: %s\n", hookFilePath);
      if (g_logFile) fprintf(g_logFile, "[HOOK] Found explicit hook path: %s\n", hookFilePath);

      // Convert backslashes for Python
      char pyHookPath[MAX_PATH];
      strncpy(pyHookPath, hookFilePath, MAX_PATH - 1);
      pyHookPath[MAX_PATH - 1] = '\0';
      for (char *p = pyHookPath; *p; ++p) if (*p == '\\') *p = '/';

      char execCmd[8192]; // INCREASED SIZE TO PREVENT OVERFLOW
      snprintf(execCmd, sizeof(execCmd), 
               "import sys, os\n"
               "print('--- Explicit Hook Execution Start ---')\n"
               "path = r'%s'\n"
               "print('Target Hook File:', path)\n"
               "if os.path.exists(path):\n"
               "    try:\n"
               "        with open(path, 'r', encoding='utf-8') as f:\n"
               "            code = f.read()\n"
               "            print('Read', len(code), 'bytes from hook file')\n"
               "            exec(compile(code, path, 'exec'), {'__name__': '__main__', '__file__': path})\n"
               "        print('Explicit execution REACHED END OF SCRIPT')\n"
               "    except Exception as e:\n"
               "        print('EXPLICIT EXECUTION ERROR:', e)\n"
               "        import traceback\n"
               "        traceback.print_exc()\n"
               "        raise\n"
               "else:\n"
               "    print('Hook file not found at:', path)\n"
               "    raise FileNotFoundError(path)\n", 
               pyHookPath);

      dbgPrintf("[HOOK] Running PyRun_SimpleString(execCmd)...\n");
      int execRes = PyRun_SimpleString(execCmd);
      dbgPrintf("[HOOK] PyRun_SimpleString(execCmd) returned: %d\n", execRes);
      if (execRes == 0) {
        PyGILState_Release(gilState);
        dbgPrintf("[HOOK] Successfully executed hook file explicitly!\n");
        if (g_logFile) fprintf(g_logFile, "[HOOK] Successfully executed hook file explicitly!\n");
        MessageBoxA(NULL, "Hook injection successful (Explicit)!", "Success", MB_OK);
        return 0;
      } else {
        dbgPrintf("[HOOK] Explicit execution FAILED with code: %d\n", execRes);
        if (g_logFile) fprintf(g_logFile, "[HOOK] Explicit execution FAILED with code: %d\n", execRes);
      }
    } else {
      dbgPrintf("[HOOK] Could not find hook path in config for explicit load.\n");
      if (g_logFile) fprintf(g_logFile, "[HOOK] Could not find hook path in config for explicit load.\n");
    }

    if (PyErr_Print)
      PyErr_Print();
    PyGILState_Release(gilState);

    dbgPrintf("[HOOK] Failed to import " PYMODULE_NAME "\n");
    if (g_logFile) {
      fprintf(g_logFile, "[HOOK] Failed to import " PYMODULE_NAME
                         " - check traceback above\n");
      fflush(g_logFile);
    }
    
    // ATTEMPT TO CAPTURE TRACEBACK TO FILE (compatible version)
    if (PyRun_SimpleString) {
        const char *errorLogScript = 
            "import traceback, sys, os\n"
            "try:\n"
            "    log_path = r'C:\\pythondumps\\hook_import_error.log'\n"
            "    if not os.path.exists(r'C:\\pythondumps'):\n"
            "        try: os.makedirs(r'C:\\pythondumps')\n"
            "        except: log_path = r'C:\\Users\\Public\\pythondumps\\hook_import_error.log'\n"
            "    \n"
            "    with open(log_path, 'w') as f:\n"
            "        f.write('HOOK IMPORT FAILURE REPORT\\n')\n"
            "        f.write('==========================\\n')\n"
            "        f.write('Traceback:\\n')\n"
            "        f.write(traceback.format_exc())\n"
            "        f.write('\\nSYS.PATH:\\n')\n"
            "        for p in sys.path: f.write('  ' + str(p) + '\\n')\n"
            "        f.write('\\nSYS.MODULES (keys):\\n')\n"
            "        f.write(str(list(sys.modules.keys())))\n"
            "except Exception as e:\n"
            "    pass\n";
            
        PyRun_SimpleString(errorLogScript);
    }

    MessageBoxA(NULL, "Failed to import " PYMODULE_NAME "\nCheck hook_output.log", "Hook Error", MB_ICONEXCLAMATION);
    return 1;
  }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    HANDLE hThread = CreateThread(nullptr, 0, hookImpl, nullptr, 0, nullptr);
    if (hThread)
      CloseHandle(hThread);
  }
  return TRUE;
}
