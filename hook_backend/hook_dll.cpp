/**
 * hook_dll.cpp
 * Automatically detects and sets PYTHONHOME based on python.exe location
 * Redirects stdout/stderr to hook_output.log
 *
 * FIXED: Ensures PYTHONHOME is correctly passed to PyRun_SimpleString to fix
 * ModuleNotFoundError for standard library modules like 'concurrent.futures'.
 */

#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h> // For strcasecmp and strtok
#include <tlhelp32.h>
#include <windows.h>

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

    // Also set PYTHONPATH
    char pythonPath[MAX_PATH * 2];
    snprintf(pythonPath, sizeof(pythonPath), "%s\\Lib;%s\\Lib\\site-packages",
             pythonHome, pythonHome);
    SetEnvironmentVariableA("PYTHONPATH", pythonPath);
    dbgPrintf("[HOOK] Set PYTHONPATH=%s\n", pythonPath);
  } else {
    dbgPrintf("[HOOK] Could not auto-detect PYTHONHOME\n");
  }
}

// ... (SetupStdoutStderrToLog function remains the same) ...

static bool SetupStdoutStderrToLog(char *outLogPath) {
  // Try to use C:\pythondumps for visibility
  char logDir[] = "C:\\pythondumps";
  CreateDirectoryA(logDir, NULL);

  char logPath[MAX_PATH];
  snprintf(logPath, MAX_PATH, "%s\\hook_dll.log", logDir);

  // Fallback if C: is not writable? Unlikely but possible.
  // Use Append mode
  g_logFile = fopen(logPath, "a");
  if (!g_logFile) {
    // Fallback to local dir
    snprintf(logPath, MAX_PATH, ".\\hook_dll.log");
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
    for (char *p = pyHomePath; *p; ++p) {
      if (*p == '\\')
        *p = '/';
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
    if (res != 0) {
      dbgPrintf("[HOOK] Failed to run Python setup snippet\n");
    }
  }

  // Import the hook module
  void *hook_module = PyImport_ImportModule(PYMODULE_NAME);

  if (hook_module) {
    Py_DecRef(hook_module);
    PyGILState_Release(gilState);

    dbgPrintf("[HOOK] Successfully imported " PYMODULE_NAME "\n");
    if (g_logFile) {
      fprintf(g_logFile, "[HOOK] Successfully imported " PYMODULE_NAME "\n");
      fflush(g_logFile);
    }

    MessageBoxA(NULL, "Hook injection successful!", "Success", MB_OK);
    return 0;
  } else {
    if (PyErr_Print)
      PyErr_Print();
    PyGILState_Release(gilState);

    dbgPrintf("[HOOK] Failed to import " PYMODULE_NAME "\n");
    if (g_logFile) {
      fprintf(g_logFile, "[HOOK] Failed to import " PYMODULE_NAME
                         " - check traceback above\n");
      fflush(g_logFile);
    }

    MessageBoxA(NULL,
                "Failed to import " PYMODULE_NAME "\nCheck hook_output.log",
                "Hook Error", MB_ICONEXCLAMATION);
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
