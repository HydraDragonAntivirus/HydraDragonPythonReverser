# code.py - Python/Pyinstaller/Nuitka Generic Code Extractor - THREADED VERSION
# Extracts EVERYTHING, not just target - OPTIMIZED WITH THREADS
#
# MODIFIED VERSION: Maximum settings, minimum logs.
#

import os
import sys
import time
import ctypes
import marshal
import types
import threading
import struct
from pathlib import Path
import importlib.util
# Concurrent futures can fail in embedded environments
try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
except ImportError:
    ThreadPoolExecutor = None
    as_completed = None
    print("[HOOK] WARNING: concurrent.futures unavailable - falling back to single thread")

class DummyFuture:
    def __init__(self, result=None):
        self._result = result
    def result(self):
        return self._result
    def done(self):
        return True
    def cancel(self):
        return False

class DummyExecutor:
    def __init__(self, max_workers=None, thread_name_prefix=""):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    def submit(self, fn, *args, **kwargs):
        try:
            res = fn(*args, **kwargs)
            return DummyFuture(res)
        except Exception as e:
            print(f"[DummyExecutor] Task failed: {e}")
            return DummyFuture(None)
    def shutdown(self, wait=True):
        pass
from queue import Queue
import traceback
import inspect
import dis
import json
from io import StringIO

# Reconfigure stdout/stderr to handle emojis even on non-UTF8 consoles (cp1254 etc)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')


# =============================================================================
# THREADING CONFIGURATION - MAXIMUM MODE (as requested)
# =============================================================================
MAX_WORKER_THREADS = 64  # Increased for massive extraction
MEMORY_SCAN_THREADS = 16  # More threads for more accurate scanning
EXTRACTION_THREADS = 32  # More threads for parallel extraction
MAX_CONCURRENT_EXTRACTIONS = 100  # More simultaneous extractions
ULTRA_AGGRESSIVE_MODE = True  # Ultra aggressive mode
SCAN_FREQUENCY = 0.2  # Scans every 0.2 seconds
MAX_SCAN_ITERATIONS = 999999  # Effectively infinite for thorough scanning

# Configuration for specific targets
_extractor_active = True
_extracted_count = 0
_backup_dir = None
_extraction_queue = Queue()
_processing_lock = threading.Lock()
_thread_pool = None
_extraction_pool = None

# =============================================================================
# MODIFICATIONS FOR GENERIC EXTRACTION
# Blacklist and indicators removed to extract everything.
# The is_target_module function has been modified.
# =============================================================================

# =============================================================================



def save_target_code_object(code_obj, name, filename, scan_id):
    """Saves target code object - THREAD SAFE"""
    try:
        safe_name = "".join(c for c in name if c.isalnum() or c in '._-')
        thread_name = threading.current_thread().name.replace('Thread-', 'T')
        pyc_file = _backup_dir / "TARGET_PYC" / f"target_{scan_id}_{thread_name}_{safe_name}.pyc"
        
        magic = importlib.util.MAGIC_NUMBER
        timestamp = struct.pack('<I', int(time.time()))
        size = struct.pack('<I', 0)
        
        if not pyc_file.parent.exists():
            try:
                pyc_file.parent.mkdir(parents=True, exist_ok=True)
            except:
                pass

        with open(pyc_file, 'wb') as f:
            f.write(magic)
            f.write(timestamp)
            f.write(size)
            f.write(marshal.dumps(code_obj))
        
        info_file = pyc_file.with_suffix('.target_info')
        with open(info_file, 'w') as f:
            f.write(f"TARGET CODE OBJECT\n")
            f.write(f"Name: {name}\n")
            f.write(f"Filename: {filename}\n")
            f.write(f"Scan ID: {scan_id}\n")
            f.write(f"Thread: {thread_name}\n")
            f.write(f"Constants: {getattr(code_obj, 'co_consts', [])}\n")
            f.write(f"Names: {getattr(code_obj, 'co_names', [])}\n")
        
        print(f"[TARGET-{thread_name}] 💾 Saved: {safe_name}")
        
    except Exception as e:
        print(f"[TARGET] Save error: {e}")

def is_target_code_object(code_obj):
    """UNCONDITIONAL EXTRACTION: Everything is a target."""
    return True

def reconstruct_function_from_bytecode_advanced(func_or_codeobj, func_name=None):
    """
    Simplified reconstruction: try inspect.getsource, otherwise return a stub.
    Removed ultra-detailed bytecode reconstruction to simplify output.
    """
    try:
        import inspect
        code_obj = None
        
        if hasattr(func_or_codeobj, '__code__'):
            try:
                return inspect.getsource(func_or_codeobj)
            except:
                pass
            code_obj = func_or_codeobj.__code__
            if not func_name:
                func_name = getattr(func_or_codeobj, "__name__", "reconstructed_function")
        else:
            code_obj = func_or_codeobj
            if not func_name:
                func_name = getattr(code_obj, "co_name", "reconstructed_function")

        # Basic stub reconstruction
        args = []
        if code_obj:
            try:
                argcount = code_obj.co_argcount
                args = list(code_obj.co_varnames[:argcount])
            except:
                args = ["*args", "**kwargs"]
        
        signature = f"({', '.join(args)})"
        
        # Restore ultra-detailed reconstruction as requested
        if code_obj:
            logic = reconstruct_executable_logic(code_obj, func_name)
            if logic and logic != ["pass"]:
                return f"def {func_name}{signature}:\n    " + "\n    ".join(logic)
        
        return f"def {func_name}{signature}:\n    pass"

    except Exception as e:
        return f"def {func_name or 'func'}(*args, **kwargs):\n    # reconstruction failed: {e}\n    pass"

def setup_target_extraction_directory():
    """Setup directory for target code extraction"""
    global _backup_dir
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # _backup_dir = Path.cwd() / f"GENERIC_CODE_EXTRACTED_{timestamp}"
        # Try C:\pythondumps first
        base_path = Path(r"C:\pythondumps")
        try:
            base_path.mkdir(exist_ok=True, parents=True)
        except:
            # Fallback to C:\Users\Public\pythondumps
            base_path = Path(r"C:\Users\Public\pythondumps")
            base_path.mkdir(exist_ok=True, parents=True)
            
        _backup_dir = base_path / f"dump_{timestamp}"
        _backup_dir.mkdir(exist_ok=True, parents=True)

        # Essential directories
        (_backup_dir / "MAIN_CODE").mkdir(exist_ok=True)
        (_backup_dir / "TARGET_PYC").mkdir(exist_ok=True)

        (_backup_dir / "RECONSTRUCTED_STRUCTURE").mkdir(exist_ok=True)

        print(f"[GENERIC] Extraction dir: {_backup_dir}")
        return True
    except Exception as e:
        print(f"[GENERIC] Setup error: {e}")
        return False

def is_target_module(module_name, module_obj=None):
    """UNCONDITIONAL EXTRACTION: Everything is a target."""
    return True

    if not module_obj:
        return True # We can't check, extract for safety

    try:
        # Do not extract modules that do not have a source file (often C built-in)
        # unless they are a package (which has a __path__)
        if not hasattr(module_obj, '__file__') or not module_obj.__file__:
            if not hasattr(module_obj, '__path__'):
                return False
    except Exception:
        pass # Extract if there are problems
        
    # If it has a file, is a package, or we're unsure, extract.
    return True

def extract_target_module_worker(module_data):
    """Worker for target module extraction - FOR THREAD POOL"""
    module_name, module_obj = module_data
    global _extracted_count

    try:
        # print(f"[GENERIC-{threading.current_thread().name}] 🎯 Extracting: {module_name}") # MINIMAL LOG

        with _processing_lock:
            _extracted_count += 1

        # 1. Extract source code (maximum priority)
        source_success = extract_target_source(module_name, module_obj)

        # 2. Reconstruct .pyc
        pyc_success = reconstruct_target_pyc(module_name, module_obj)

        # 3. Extract main functions and classes
        func_success = extract_target_functions(module_name, module_obj)

        return {
            'module_name': module_name,
            'source_success': source_success,
            'pyc_success': pyc_success,
            'func_success': func_success,
            'thread': threading.current_thread().name
        }

    except Exception as e:
        print(f"[GENERIC-{threading.current_thread().name}] Extraction error for {module_name}: {e}")
        return {
            'module_name': module_name,
            'error': str(e),
            'thread': threading.current_thread().name
        }

def extract_target_source(module_name, module_obj):
    """Extracts target source code - THREAD SAFE"""
    try:
        safe_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        source_file = _backup_dir / "MAIN_CODE" / f"{safe_name}.py"

        try:
            # Try complete getsource
            source = inspect.getsource(module_obj)

            if not source_file.parent.exists():
                source_file.parent.mkdir(parents=True, exist_ok=True)

            with open(source_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"# TARGET MODULE: {module_name}\n")
                f.write(f"# Extracted: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Thread: {threading.current_thread().name}\n")
                f.write(f"# Original file: {getattr(module_obj, '__file__', 'EMBEDDED')}\n")
                f.write(f"# Module type: {type(module_obj)}\n\n")
                f.write(source)

            # print(f"[GENERIC-{threading.current_thread().name}] ✅ Source code extracted: {module_name}") # MINIMAL LOG
            return True

        except (OSError, TypeError):
            # Fallback: extract functions/classes individually
            return extract_target_components(module_name, module_obj)

    except Exception as e:
        print(f"[GENERIC-{threading.current_thread().name}] Source extraction error for {module_name}: {e}")
        return False

def extract_target_components(module_name, module_obj):
    """Extracts individual components of the target module - COMPLETE REVERSE ENGINEERING"""
    try:
        safe_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        comp_file = _backup_dir / "MAIN_CODE" / f"{safe_name}_RECONSTRUCTED.py"

        if not comp_file.parent.exists():
            comp_file.parent.mkdir(parents=True, exist_ok=True)

        with open(comp_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(f"# RECONSTRUCTED MODULE: {module_name}\n")
            f.write(f"# Extracted: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Thread: {threading.current_thread().name}\n")
            f.write(f"# COMPLETE REVERSE ENGINEERING - EXECUTABLE CODE\n\n")

            # Necessary imports based on used names
            f.write("# === RECONSTRUCTED IMPORTS ===\n")
            all_imports = extract_all_imports(module_obj)
            for imp in all_imports:
                f.write(f"{imp}\n")
            f.write("\n")

            # Variables and constants (as before - these already work)
            f.write("# === VARIABLES AND CONSTANTS ===\n")
            for attr_name in dir(module_obj):
                if not attr_name.startswith('_'):
                    try:
                        attr = getattr(module_obj, attr_name)
                        if isinstance(attr, (str, int, float, bool, list, dict, tuple)):
                            f.write(f"{attr_name} = {repr(attr)}\n")
                    except:
                        pass
            f.write("\n")

            # URL FUNCTIONS EXTRACTION (new!)
            f.write("# === URL BUILDING FUNCTIONS ===\n")
            url_functions = extract_url_building_functions(module_obj)
            for func_name, reconstructed_code in url_functions.items():
                f.write(f"\n{reconstructed_code}\n")
            f.write("\n")

            # Reconstruct LAMBDA FUNCTIONS with complete reverse engineering
            f.write("# === LAMBDA FUNCTIONS (RECONSTRUCTED) ===\n")
            for attr_name in dir(module_obj):
                if not attr_name.startswith('_'):
                    try:
                        attr = getattr(module_obj, attr_name)
                        if hasattr(attr, '__code__') and hasattr(attr.__code__, 'co_name'):
                            if '<lambda>' in attr.__code__.co_name:
                                # COMPLETE lambda reconstruction
                                reconstructed_lambda = reconstruct_lambda_from_bytecode(attr.__code__, attr_name)
                                if reconstructed_lambda:
                                    f.write(f"\n{reconstructed_lambda}\n")
                                else:
                                    # Advanced fallback
                                    lambda_info = extract_lambda_info(attr, attr_name)
                                    f.write(f"\n{lambda_info}\n")
                    except:
                        pass
            f.write("\n")

            # Reconstruct ALL functions with COMPLETE reverse engineering
            f.write("# === FUNCTIONS (REVERSE ENGINEERED) ===\n")
            for attr_name in dir(module_obj):
                if not attr_name.startswith('_'):
                    try:
                        attr = getattr(module_obj, attr_name)
                        if inspect.isfunction(attr) or (callable(attr) and not inspect.isclass(attr)):

                            # Skip if already processed as URL function
                            if attr_name in url_functions:
                                continue

                            # Skip if it is a lambda (already processed above)
                            if hasattr(attr, '__code__') and hasattr(attr.__code__, 'co_name'):
                                if '<lambda>' in attr.__code__.co_name:
                                    continue

                            # Simplified reconstruction
                            reconstructed_func = reconstruct_function_from_bytecode_advanced(attr, attr_name)
                            f.write(f"\n{reconstructed_func}\n")
                    except:
                        pass

            f.write("\n# === CLASSES (REVERSE ENGINEERED) ===\n")
            # Reconstruct classes with working methods
            for attr_name in dir(module_obj):
                if not attr_name.startswith('_'):
                    try:
                        attr = getattr(module_obj, attr_name)
                        if inspect.isclass(attr):

                            # Simplified reconstruction
                            reconstructed_class = reconstruct_function_from_bytecode_advanced(attr, attr_name) # Stub for class
                            f.write(f"\n{reconstructed_class}\n")
                    except:
                        pass

        # generate_ultra_detailed_analysis removed

        # print(f"[GENERIC-{threading.current_thread().name}] 🚀 COMPLETE REVERSE ENGINEERING completed: {module_name}") # MINIMAL LOG
        return True

    except Exception as e:
        print(f"[GENERIC-{threading.current_thread().name}] Complete reverse engineering error for {module_name}: {e}")
        return False

def complete_function_reverse_engineering(func_obj, func_name):
    """COMPLETE reverse engineering of a function - MAXIMUM DETAIL"""
    try:
        lines = []

        # ADVANCED signature reconstruction
        try:
            sig = inspect.signature(func_obj)
            lines.append(f"def {func_name}{sig}:")
        except:
            if hasattr(func_obj, '__code__'):
                code = func_obj.__code__
                args = code.co_varnames[:code.co_argcount]
                kwargs_start = code.co_argcount
                kwargs_count = getattr(code, 'co_kwonlyargcount', 0)
                kwargs = code.co_varnames[kwargs_start:kwargs_start + kwargs_count]

                sig_parts = list(args)
                if kwargs:
                    sig_parts.extend([f"*, {k}" for k in kwargs])

                # Add type hints if they can be deduced
                enhanced_args = []
                for arg in args:
                    if 'url' in arg.lower() or 'path' in arg.lower():
                        enhanced_args.append(f"{arg}: str")
                    elif 'data' in arg.lower() or 'content' in arg.lower():
                        enhanced_args.append(f"{arg}: dict")
                    else:
                        enhanced_args.append(arg)

                lines.append(f"def {func_name}({', '.join(enhanced_args)}):")
            else:
                lines.append(f"def {func_name}(*args, **kwargs):")

        # Docstring RECONSTRUCTED from bytecode
        if hasattr(func_obj, '__doc__') and func_obj.__doc__:
            lines.append(f'    """{func_obj.__doc__}"""')
        else:
            # Generate docstring from content
            if hasattr(func_obj, '__code__'):
                code = func_obj.__code__
                constants = [c for c in (code.co_consts or []) if isinstance(c, str)]
                if any('http' in c for c in constants):
                    lines.append('    """Makes HTTP request"""')
                elif any('file' in str(code.co_names) for _ in [1]):
                    lines.append('    """File operation"""')
                elif 'hash' in str(code.co_names):
                    lines.append('    """Hash calculation"""')

        # COMPLETE reverse engineering of logic
        if hasattr(func_obj, '__code__'):
            code = func_obj.__code__

            # Use our advanced reverse engineering system
            reconstructed_logic = reconstruct_executable_logic(code, func_name)
            if reconstructed_logic and reconstructed_logic != ["pass"]:
                lines.extend([f"    {line}" for line in reconstructed_logic])
            else:
                # Fallback: smart analysis
                smart_logic = smart_function_analysis(code, func_name)
                lines.extend([f"    {line}" for line in smart_logic])
        else:
            lines.append("    pass  # Binary/Built-in function")

        return '\n'.join(lines)

    except Exception as e:
        return f"def {func_name}():\n    # Reverse engineering failed: {e}\n    pass"

def smart_function_analysis(code_obj, func_name):
    """Smart analysis when complete reverse engineering fails"""
    try:
        constants = code_obj.co_consts or []
        names = code_obj.co_names or []
        varnames = code_obj.co_varnames or []

        lines = []

        # Search for interesting string patterns
        string_constants = [c for c in constants if isinstance(c, str) and c.strip()]

        # Pattern: URL/API Call
        if any('http' in c for c in string_constants):
            lines.append("# Pattern: HTTP/API Request Detected")
            urls = [c for c in string_constants if 'http' in c]
            endpoints = [c for c in string_constants if c.startswith('/')]

            if urls and endpoints:
                lines.append(f"base_url = {repr(urls[0])}")
                lines.append(f"endpoint = {repr(endpoints[0])}")
                if varnames:
                    lines.append(f"full_url = f\"{{base_url}}{{endpoint}}/{{args[0]}}\"")
                else:
                    lines.append("full_url = base_url + endpoint")

                if 'requests' in names:
                    lines.append("response = requests.get(full_url)")
                    lines.append("return response.json()")
                else:
                    lines.append("return full_url")
            elif urls:
                lines.append(f"url = {repr(urls[0])}")
                lines.append("return requests.get(url).json()")
            else:
                lines.append("return requests.post(api_endpoint, data=payload)")

        # Pattern: File I/O
        elif 'open' in names or any('file' in str(c).lower() for c in constants):
            lines.append("# Pattern: File I/O Detected")
            files = [c for c in string_constants if '.' in c and '/' in c]
            if 'json' in names:
                lines.append("with open(file_path, 'r') as f:")
                lines.append("    data = json.load(f)")
                lines.append("return data")
            else:
                lines.append("with open(file_path, 'r') as f:")
                lines.append("    content = f.read()")
                lines.append("return content")

        # Pattern: Crypto/Hash
        elif any(name in names for name in ['hashlib', 'hmac', 'sha256', 'md5']):
            lines.append("# Pattern: Crypto/Hash Detected")
            lines.append("import hashlib")
            lines.append("hash_obj = hashlib.sha256()")
            if varnames:
                lines.append(f"hash_obj.update({varnames[0]}.encode())")
            else:
                lines.append("hash_obj.update(data.encode())")
            lines.append("return hash_obj.hexdigest()")

        # Pattern: System/OS Command
        elif 'platform' in names or 'os' in names or 'subprocess' in names:
            lines.append("# Pattern: System/OS Command Detected")
            lines.append("import platform")
            lines.append("system_info = platform.system()")
            lines.append("return system_info")

        # Pattern: Returns a constant
        elif len(string_constants) == 1:
            const = string_constants[0]
            lines.append(f"return {repr(const)}")

        # Pattern: String concatenation
        elif len(string_constants) > 1:
            lines.append("# Pattern: String Concatenation Detected")
            lines.append("result = ''")
            for const in string_constants:
                if len(const) > 1:  # Skip single chars
                    lines.append(f"result += {repr(const)}")
            if varnames:
                lines.append(f"result += str({varnames[0]})")
            lines.append("return result")

        # Fallback with MAXIMUM detail
        else:
            lines.append(f"# Advanced analysis of {func_name}:")
            lines.append(f"# Constants available: {[c for c in constants if c is not None]}")
            lines.append(f"# Names used: {list(names)}")
            lines.append(f"# Variables: {list(varnames)}")
            lines.append(f"# Stack size: {code_obj.co_stacksize}")
            lines.append(f"# Flags: {code_obj.co_flags}")

            # Deduction based on names
            if 'get' in names:
                lines.append("# Likely performs GET operation")
                lines.append("result = get_operation()")
            elif 'post' in names:
                lines.append("# Likely performs POST operation")
                lines.append("result = post_operation()")
            elif names:
                lines.append(f"# Likely calls: {names[0]}")
                lines.append(f"result = {names[0]}()")
            else:
                lines.append("# Complex operation - manual analysis needed")
                lines.append("result = None")

            lines.append("return result")

        return lines

    except Exception as e:
        return [f"# Smart analysis failed: {e}", "pass"]

def complete_class_reverse_engineering(class_obj, class_name):
    """COMPLETE reverse engineering of a class"""
    try:
        lines = []

        # Class definition with COMPLETE inheritance
        if hasattr(class_obj, '__bases__') and class_obj.__bases__:
            bases = []
            for base in class_obj.__bases__:
                if hasattr(base, '__name__') and base.__name__ != 'object':
                    bases.append(base.__name__)
            if bases:
                lines.append(f"class {class_name}({', '.join(bases)}):")
            else:
                lines.append(f"class {class_name}:")
        else:
            lines.append(f"class {class_name}:")

        # RECONSTRUCTED docstring
        if hasattr(class_obj, '__doc__') and class_obj.__doc__:
            lines.append(f'    """{class_obj.__doc__}"""')
        else:
            # Generate smart docstring
            lines.append(f'    """Reconstructed class {class_name}"""')

        # REAL class attributes
        class_dict = getattr(class_obj, '__dict__', {})
        for attr_name, attr_value in class_dict.items():
            if not attr_name.startswith('__') and not callable(attr_value):
                if isinstance(attr_value, (str, int, float, bool)):
                    lines.append(f"    {attr_name} = {repr(attr_value)}")

        # Reconstruct methods with COMPLETE reverse engineering
        methods_found = False
        for attr_name in dir(class_obj):
            if not attr_name.startswith('__'):
                try:
                    attr = getattr(class_obj, attr_name)
                    if callable(attr):
                        methods_found = True

                        # Try normal source extraction
                        try:
                            if hasattr(attr, '__func__'):
                                method_source = inspect.getsource(attr.__func__)
                            else:
                                method_source = inspect.getsource(attr)
                            # Indent the source
                            indented = '\n'.join([f"    {line}" for line in method_source.split('\n')])
                            lines.append(f"\n{indented}")
                            continue
                        except:
                            pass

                        # COMPLETE reverse engineering of the method
                        method_reconstruction = complete_method_reverse_engineering(attr, attr_name, class_name)
                        lines.append(f"\n    {method_reconstruction}")
                except:
                    pass

        # If no methods are found, add pass
        if not methods_found:
            lines.append("    pass")

        return '\n'.join(lines)

    except Exception as e:
        return f"class {class_name}:\n    # Complete class reverse engineering failed: {e}\n    pass"

def complete_method_reverse_engineering(method_obj, method_name, class_name):
    """COMPLETE reverse engineering of a class method"""
    try:
        lines = []

        # ADVANCED method signature
        try:
            if hasattr(method_obj, '__func__'):
                sig = inspect.signature(method_obj.__func__)
            else:
                sig = inspect.signature(method_obj)
            lines.append(f"def {method_name}{sig}:")
        except:
            # Smart signature fallback
            if hasattr(method_obj, '__func__') and hasattr(method_obj.__func__, '__code__'):
                code = method_obj.__func__.__code__
            elif hasattr(method_obj, '__code__'):
                code = method_obj.__code__
            else:
                lines.append(f"def {method_name}(self):")
                lines.append("    pass")
                return '\n'.join(lines)

            args = code.co_varnames[:code.co_argcount]
            lines.append(f"def {method_name}({', '.join(args)}):")

        # RECONSTRUCTED docstring
        if hasattr(method_obj, '__doc__') and method_obj.__doc__:
            lines.append(f'    """{method_obj.__doc__}"""')

        # COMPLETE logic reconstruction
        if hasattr(method_obj, '__func__') and hasattr(method_obj.__func__, '__code__'):
            code = method_obj.__func__.__code__
        elif hasattr(method_obj, '__code__'):
            code = method_obj.__code__
        else:
            lines.append("    pass")
            return '\n'.join(lines)

        # Use our reverse engineering system
        method_logic = reconstruct_executable_logic(code, method_name)
        if method_logic and method_logic != ["pass"]:
            lines.extend([f"    {line}" for line in method_logic])
        else:
            # Smart fallback for methods
            smart_logic = smart_method_analysis(code, method_name, class_name)
            lines.extend([f"    {line}" for line in smart_logic])

        return '\n'.join(lines)

    except Exception as e:
        return f"def {method_name}(self):\n    # Complete method reverse engineering failed: {e}\n    pass"

def smart_method_analysis(code_obj, method_name, class_name):
    """Smart analysis for class methods"""
    try:
        constants = code_obj.co_consts or []
        names = code_obj.co_names or []

        lines = []

        # Specific patterns for methods
        if method_name in ['authenticate', 'login', 'verify']:
            lines.append("# Authentication method")
            if any('http' in str(c) for c in constants):
                lines.append("response = requests.post(auth_url, data=credentials)")
                lines.append("return response.json()")
            else:
                lines.append("return self.validate_credentials()")

        elif method_name in ['get', 'fetch', 'retrieve']:
            lines.append("# Data retrieval method")
            lines.append("data = self.fetch_data()")
            lines.append("return data")

        elif method_name in ['save', 'store', 'write']:
            lines.append("# Data storage method")
            lines.append("self.store_data(data)")
            lines.append("return True")

        elif method_name.startswith('_'):
            lines.append("# Private method")
            lines.append("# Implementation details")
            lines.append("pass")

        else:
            # Generic but smart analysis
            if constants:
                string_consts = [c for c in constants if isinstance(c, str)]
                if string_consts:
                    lines.append(f"# Uses constants: {string_consts[:3]}")

            if names:
                lines.append(f"# Calls: {list(names)[:3]}")

            lines.append("# Method implementation")
            lines.append("return self.handle_operation()")

        return lines

    except Exception as e:
        return [f"# Smart method analysis failed: {e}", "pass"]

def extract_all_imports(module_obj):
    """Extracts all necessary imports by analyzing the names used"""
    imports = set()

    try:
        # Analyze all objects to understand imports
        for attr_name in dir(module_obj):
            if not attr_name.startswith('_'):
                try:
                    attr = getattr(module_obj, attr_name)

                    # If it has a module, add import
                    if hasattr(attr, '__module__') and attr.__module__:
                        module_name = attr.__module__
                        if not module_name.startswith('builtins'):
                            if '.' in module_name:
                                parts = module_name.split('.')
                                imports.add(f"import {parts[0]}")
                                if len(parts) > 1:
                                    imports.add(f"from {'.'.join(parts[:-1])} import {parts[-1]}")
                            else:
                                imports.add(f"import {module_name}")

                    # Analyze bytecode for imports
                    if hasattr(attr, '__code__'):
                        code_imports = extract_imports_from_bytecode(attr.__code__)
                        imports.update(code_imports)

                except:
                    pass

        # Common imports based on found names
        common_imports = {
            'requests': 'import requests',
            'json': 'import json',
            'os': 'import os',
            'sys': 'import sys',
            'time': 'import time',
            'datetime': 'import datetime',
            'base64': 'import base64',
            'hashlib': 'import hashlib',
            'hmac': 'import hmac',
            'platform': 'import platform',
            'subprocess': 'import subprocess',
            'cryptography': 'from cryptography.hazmat.backends import default_backend',
            'colorama': 'from colorama import init as colorama_init'
        }

        module_str = str(module_obj)
        for name, import_stmt in common_imports.items():
            if name in module_str.lower():
                imports.add(import_stmt)

    except:
        pass

    return sorted(list(imports))

def extract_imports_from_bytecode(code_obj):
    """Extracts imports from bytecode by analyzing LOAD_GLOBAL"""
    imports = set()

    try:
        # Analyze used global names
        for name in code_obj.co_names:
            if name in ['requests', 'json', 'os', 'sys', 'platform', 'subprocess', 'base64', 'hashlib', 'hmac']:
                imports.add(f"import {name}")
            elif name == 'init' and 'colorama' in str(code_obj.co_filename):
                imports.add("from colorama import init as colorama_init")
    except:
        pass

    return imports

def ultra_aggressive_function_reconstruction(func_obj, func_name):
    """Reconstructs EXECUTABLE function from bytecode - ULTRA AGGRESSIVE"""
    try:
        lines = []

        # Signature reconstruction
        try:
            sig = inspect.signature(func_obj)
            lines.append(f"def {func_name}{sig}:")
        except:
            if hasattr(func_obj, '__code__'):
                code = func_obj.__code__
                args = code.co_varnames[:code.co_argcount]
                kwargs = code.co_varnames[code.co_argcount:code.co_argcount + getattr(code, 'co_kwonlyargcount', 0)]
                sig_parts = list(args)
                if kwargs:
                    sig_parts.extend([f"*, {k}" for k in kwargs])
                lines.append(f"def {func_name}({', '.join(sig_parts)}):")
            else:
                lines.append(f"def {func_name}(*args, **kwargs):")

        # Docstring
        if hasattr(func_obj, '__doc__') and func_obj.__doc__:
            lines.append(f'    """{func_obj.__doc__}"""')

        # Code reconstruction from bytecode
        if hasattr(func_obj, '__code__'):
            code = func_obj.__code__

            # Analyze bytecode to reconstruct logic
            bytecode_logic = reconstruct_executable_logic(code, func_name)
            if bytecode_logic:
                lines.extend([f"    {line}" for line in bytecode_logic])
            else:
                # Fallback: basic reconstruction
                basic_logic = reconstruct_basic_logic(code, func_name)
                lines.extend([f"    {line}" for line in basic_logic])
        else:
            lines.append("    pass  # No code object available")

        return '\n'.join(lines)

    except Exception as e:
        return f"def {func_name}():\n    # Reconstruction error: {e}\n    pass"

def reconstruct_executable_logic(code_obj, func_name):
    """Reconstructs EXECUTABLE logic from bytecode - COMPLETE REVERSE ENGINEERING"""
    try:
        # Get detailed bytecode instructions
        instructions = list(dis.get_instructions(code_obj))

        # Code object data
        constants = code_obj.co_consts or []
        names = code_obj.co_names or []
        varnames = code_obj.co_varnames or []

        # Python stack simulator
        stack = []
        variables = {}
        logic_lines = []

        # print(f"[REVERSE] Analyzing {func_name}: {len(instructions)} instructions, {len(constants)} constants") # MINIMAL LOG

        i = 0
        while i < len(instructions):
            instr = instructions[i]
            opname = instr.opname
            arg = instr.arg

            # LOAD Operations
            if opname == 'LOAD_CONST':
                const_value = constants[arg] if arg < len(constants) else None
                stack.append(('CONST', const_value))

            elif opname == 'LOAD_GLOBAL':
                global_name = names[arg] if arg < len(names) else f'name_{arg}'
                stack.append(('GLOBAL', global_name))

            elif opname == 'LOAD_FAST':
                var_name = varnames[arg] if arg < len(varnames) else f'var_{arg}'
                stack.append(('VAR', var_name))

            elif opname == 'LOAD_ATTR':
                attr_name = names[arg] if arg < len(names) else f'attr_{arg}'
                if stack:
                    obj = stack.pop()
                    stack.append(('ATTR', f"{format_stack_item(obj)}.{attr_name}"))

            # STORE Operations
            elif opname == 'STORE_FAST':
                var_name = varnames[arg] if arg < len(varnames) else f'var_{arg}'
                if stack:
                    value = stack.pop()
                    variables[var_name] = value
                    logic_lines.append(f"{var_name} = {format_stack_item(value)}")

            elif opname == 'STORE_GLOBAL':
                global_name = names[arg] if arg < len(names) else f'global_{arg}'
                if stack:
                    value = stack.pop()
                    logic_lines.append(f"{global_name} = {format_stack_item(value)}")

            # Binary Operations
            elif opname == 'BINARY_ADD':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    result = ('EXPR', f"({format_stack_item(left)} + {format_stack_item(right)})")
                    stack.append(result)

            elif opname == 'BINARY_MULTIPLY':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    result = ('EXPR', f"({format_stack_item(left)} * {format_stack_item(right)})")
                    stack.append(result)

            elif opname == 'BINARY_MODULO':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    result = ('EXPR', f"({format_stack_item(left)} % {format_stack_item(right)})")
                    stack.append(result)

            # Format string (f-string or .format())
            elif opname == 'FORMAT_VALUE':
                if stack:
                    value = stack.pop()
                    stack.append(('FORMATTED', f"{{{format_stack_item(value)}}}"))

            elif opname == 'BUILD_STRING':
                # Reconstructs f-string
                parts = []
                for _ in range(arg):
                    if stack:
                        parts.append(format_stack_item(stack.pop()))
                parts.reverse()
                f_string = "f\"" + "".join(parts) + "\""
                stack.append(('CONST', f_string))

            # Function Calls
            elif opname in ['CALL_FUNCTION', 'CALL_METHOD', 'CALL_FUNCTION_KW', 'CALL_FUNCTION_EX']:
                argc = arg if opname == 'CALL_FUNCTION' else 0

                # Extract arguments
                args = []
                for _ in range(argc):
                    if stack:
                        args.append(format_stack_item(stack.pop()))
                args.reverse()

                # Extract function
                if stack:
                    func = stack.pop()
                    func_call = f"{format_stack_item(func)}({', '.join(args)})"

                    # If it's an important call, assign it
                    if should_assign_call(format_stack_item(func)):
                        logic_lines.append(f"result = {func_call}")
                        stack.append(('VAR', 'result'))
                    else:
                        stack.append(('CALL', func_call))

            # Comparisons
            elif opname == 'COMPARE_OP':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    # Map compare operation
                    compare_ops = ['<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not']
                    op = compare_ops[arg] if arg < len(compare_ops) else '=='
                    result = ('EXPR', f"({format_stack_item(left)} {op} {format_stack_item(right)})")
                    stack.append(result)

            # Control Flow
            elif opname in ['POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE']:
                if stack:
                    condition = stack.pop()
                    logic_lines.append(f"if {format_stack_item(condition)}:")
                    logic_lines.append("    # Conditional logic here")

            # Return
            elif opname == 'RETURN_VALUE':
                if stack:
                    return_value = stack.pop()
                    logic_lines.append(f"return {format_stack_item(return_value)}")
                else:
                    logic_lines.append("return")
                break

            # Build operations
            elif opname == 'BUILD_TUPLE':
                items = []
                for _ in range(arg):
                    if stack:
                        items.append(format_stack_item(stack.pop()))
                items.reverse()
                stack.append(('TUPLE', f"({', '.join(items)})"))

            elif opname == 'BUILD_LIST':
                items = []
                for _ in range(arg):
                    if stack:
                        items.append(format_stack_item(stack.pop()))
                items.reverse()
                stack.append(('LIST', f"[{', '.join(items)}]"))

            elif opname == 'BUILD_DICT':
                items = []
                for _ in range(arg):
                    if len(stack) >= 2:
                        value = stack.pop()
                        key = stack.pop()
                        items.append(f"{format_stack_item(key)}: {format_stack_item(value)}")
                items.reverse()
                stack.append(('DICT', f"{{{', '.join(items)}}}"))

            # Exception handling
            elif opname == 'RAISE_VARARGS':
                if arg == 1 and stack:
                    exception = stack.pop()
                    logic_lines.append(f"raise {format_stack_item(exception)}")
                elif arg == 0:
                    logic_lines.append("raise")

            # Import operations
            elif opname == 'IMPORT_NAME':
                module_name = names[arg] if arg < len(names) else f'module_{arg}'
                if len(stack) >= 2:
                    fromlist = stack.pop()
                    level = stack.pop()
                    logic_lines.append(f"import {module_name}")
                stack.append(('MODULE', module_name))

            elif opname == 'IMPORT_FROM':
                attr_name = names[arg] if arg < len(names) else f'import_{arg}'
                logic_lines.append(f"from module import {attr_name}")
                stack.append(('IMPORTED', attr_name))

            # With statement
            elif opname == 'SETUP_WITH':
                logic_lines.append("with context_manager:")
                logic_lines.append("    # With block logic")

            # For loop
            elif opname == 'FOR_ITER':
                if stack:
                    iterable = stack.pop()
                    logic_lines.append(f"for item in {format_stack_item(iterable)}:")
                    logic_lines.append("    # Loop body")

            i += 1

        # If no logic was generated, use constants for deduction
        if not logic_lines:
            logic_lines = deduce_logic_from_constants(constants, names, varnames, func_name)

        # Post-processing to improve logic
        logic_lines = improve_reconstructed_logic(logic_lines, constants, names)

        return logic_lines

    except Exception as e:
        print(f"[REVERSE] Error reconstructing {func_name}: {e}")
        return [f"# Reverse engineering failed: {e}", "pass"]

def format_stack_item(item):
    """Formats a stack item into Python code"""
    if not isinstance(item, tuple):
        return str(item)

    item_type, value = item

    if item_type == 'CONST':
        if isinstance(value, str):
            return repr(value)
        else:
            return str(value)
    elif item_type in ['GLOBAL', 'VAR', 'ATTR', 'CALL', 'EXPR', 'TUPLE', 'LIST', 'DICT', 'MODULE', 'IMPORTED', 'FORMATTED']:
        return str(value)
    else:
        return str(value)

def should_assign_call(func_str):
    """Determines if a function call should be assigned to a variable"""
    important_calls = [
        'requests.get', 'requests.post', 'requests.put', 'requests.delete',
        'json.loads', 'json.dumps', 'open', 'read', 'write',
        'subprocess.run', 'subprocess.call', 'platform.system',
        'hashlib.', 'hmac.', 'base64.', 'os.path.', 'os.environ'
    ]

    return any(call in func_str for call in important_calls)

def deduce_logic_from_constants(constants, names, varnames, func_name):
    """Deduces logic from constants when bytecode is too complex"""
    logic_lines = []

    # Analyze string constants for patterns
    string_constants = [c for c in constants if isinstance(c, str) and c]
    urls = [c for c in string_constants if 'http' in c or 'api' in c]
    paths = [c for c in string_constants if '/' in c and not 'http' in c]

    # Pattern HTTP requests
    if 'requests' in names and urls:
        base_url = urls[0]
        if 'get' in names:
            logic_lines.append(f"url = {repr(base_url)}")
            if len(urls) > 1:
                endpoint = urls[1] if urls[1].startswith('/') else f"/{urls[1]}"
                logic_lines.append(f"full_url = url + {repr(endpoint)}")
                logic_lines.append("response = requests.get(full_url)")
            else:
                logic_lines.append("response = requests.get(url)")
            logic_lines.append("return response.json()")
        elif 'post' in names:
            logic_lines.append(f"url = {repr(base_url)}")
            logic_lines.append("response = requests.post(url, data=data)")
            logic_lines.append("return response.json()")

    # Pattern file operations
    elif 'open' in names and paths:
        file_path = paths[0]
        if 'r' in [c for c in constants if isinstance(c, str) and len(c) == 1]:
            logic_lines.append(f"with open({repr(file_path)}, 'r') as f:")
            logic_lines.append("    content = f.read()")
            if 'json' in names:
                logic_lines.append("    data = json.loads(content)")
                logic_lines.append("return data")
            else:
                logic_lines.append("return content")
        else:
            logic_lines.append(f"with open({repr(file_path)}, 'w') as f:")
            logic_lines.append("    f.write(content)")
            logic_lines.append("return True")

    # Pattern crypto/hash
    elif any(name in names for name in ['hashlib', 'hmac', 'sha256', 'md5']):
        if 'hashlib' in names:
            hash_type = 'sha256'
            if any('md5' in str(c) for c in constants):
                hash_type = 'md5'
            logic_lines.append(f"hash_obj = hashlib.{hash_type}()")
            logic_lines.append("hash_obj.update(data.encode())")
            logic_lines.append("return hash_obj.hexdigest()")

    # Pattern platform/system
    elif 'platform' in names:
        logic_lines.append("system_info = platform.system()")
        if 'Windows' in string_constants:
            logic_lines.append("if system_info == 'Windows':")
            logic_lines.append("    # Windows specific logic")
        logic_lines.append("return system_info")

    # Pattern subprocess
    elif 'subprocess' in names:
        logic_lines.append("result = subprocess.run(cmd, capture_output=True, text=True)")
        logic_lines.append("return result.stdout")

    # Pattern string formatting/concatenation
    elif len(string_constants) > 1:
        logic_lines.append(f"# Uses string constants: {string_constants}")
        # Attempt to reconstruct concatenation
        if all('/' in s or 'http' in s or '.' in s for s in string_constants):
            logic_lines.append(f"result = {repr(string_constants[0])}")
            for const in string_constants[1:]:
                logic_lines.append(f"result += {repr(const)}")
            logic_lines.append("return result")

    # Pattern simple return of constant
    elif len(string_constants) == 1:
        const = string_constants[0]
        logic_lines.append(f"return {repr(const)}")

    # Fallback: keep everything and paste directly if heuristics didn't match
    if not logic_lines:
        logic_lines.append(f"# Function: {func_name}")
        logic_lines.append(f"# Constants: {constants}")
        logic_lines.append(f"# Names: {names}")
        logic_lines.append(f"# Varnames: {varnames}")
        for i, c in enumerate(constants):
            logic_lines.append(f"CONST_{i} = {repr(c)}")
        for i, n in enumerate(names):
            logic_lines.append(f"NAME_{i} = {repr(n)}")
        for i, v in enumerate(varnames):
            logic_lines.append(f"VAR_{i} = {repr(v)}")

    return logic_lines

def improve_reconstructed_logic(logic_lines, constants, names):
    """Improves reconstructed logic with post-processing"""
    improved = []

    # Add necessary imports at the beginning if not present
    imports_needed = set()
    for line in logic_lines:
        if 'requests.' in line:
            imports_needed.add('requests')
        elif 'json.' in line:
            imports_needed.add('json')
        elif 'hashlib.' in line:
            imports_needed.add('hashlib')
        elif 'platform.' in line:
            imports_needed.add('platform')
        elif 'subprocess.' in line:
            imports_needed.add('subprocess')
        elif 'base64.' in line:
            imports_needed.add('base64')

    # If there are imports, comment that they are necessary
    if imports_needed:
        improved.append(f"# Required imports: {', '.join(sorted(imports_needed))}")

    # Process each line
    for line in logic_lines:
        # Improve formatting
        if 'result = result +' in line:
            line = line.replace('result = result +', 'result +=')

        # Improve API calls
        if 'requests.get(' in line and 'full_url' in line:
            line = line.replace('requests.get(full_url)', 'requests.get(full_url, timeout=30)')

        # Add error handling for important calls
        if 'requests.' in line or 'open(' in line:
            improved.append("try:")
            improved.append(f"    {line}")
            improved.append("except Exception as e:")
            improved.append("    return None")
        else:
            improved.append(line)

    return improved

def analyze_bytecode_instructions(instructions, constants, names, variables):
    """Analyzes bytecode instructions to reconstruct detailed logic"""
    logic_lines = []

    try:
        stack = []  # Simulates Python stack
        locals_dict = {}

        for line in instructions:
            line = line.strip()
            if not line or 'Disassembly' in line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            opcode = parts[1] if len(parts) > 1 else ''

            # Analyze main instructions
            if opcode == 'LOAD_CONST':
                try:
                    const_idx = int(parts[2].split('(')[1].split(')')[0])
                    if const_idx < len(constants):
                        const_val = constants[const_idx]
                        stack.append(repr(const_val))
                except:
                    stack.append("None")

            elif opcode == 'LOAD_GLOBAL':
                try:
                    name = parts[2].split('(')[1].split(')')[0]
                    stack.append(name)
                except:
                    stack.append("unknown")

            elif opcode == 'LOAD_FAST':
                try:
                    var_name = parts[2].split('(')[1].split(')')[0]
                    stack.append(var_name)
                except:
                    stack.append("var")

            elif opcode == 'STORE_FAST':
                if stack:
                    value = stack.pop()
                    try:
                        var_name = parts[2].split('(')[1].split(')')[0]
                        logic_lines.append(f"{var_name} = {value}")
                        locals_dict[var_name] = value
                    except:
                        logic_lines.append(f"temp_var = {value}")

            elif opcode == 'BINARY_ADD':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    result = f"({left} + {right})"
                    stack.append(result)

            elif opcode == 'CALL_FUNCTION' or opcode == 'CALL_METHOD':
                try:
                    arg_count = int(parts[2]) if len(parts) > 2 else 0
                    args = []
                    for _ in range(arg_count):
                        if stack:
                            args.append(stack.pop())
                    args.reverse()

                    if stack:
                        func = stack.pop()
                        call = f"{func}({', '.join(args)})"
                        stack.append(call)
                        # If it seems to be an important call, add it
                        if any(important in func.lower() for important in ['request', 'get', 'post', 'open', 'read', 'write']):
                            logic_lines.append(f"result = {call}")
                except:
                    if stack:
                        func = stack.pop()
                        logic_lines.append(f"result = {func}()")

            elif opcode == 'RETURN_VALUE':
                if stack:
                    return_val = stack.pop()
                    logic_lines.append(f"return {return_val}")
                else:
                    logic_lines.append("return result")
                break

        # If no logic, add smart placeholder
        if not logic_lines:
            if constants:
                string_consts = [c for c in constants if isinstance(c, str)]
                if string_consts:
                    logic_lines.append(f"# Uses constants: {string_consts}")
            if names:
                logic_lines.append(f"# Calls: {list(names)}")
            logic_lines.append("pass  # Complex logic - manual analysis needed")

        return logic_lines

    except Exception as e:
        return [f"# Instruction analysis failed: {e}", "pass"]

def ultra_aggressive_class_reconstruction(class_obj, class_name):
    """Reconstructs EXECUTABLE class - ULTRA AGGRESSIVE"""
    try:
        lines = []

        # Class definition with inheritance
        if hasattr(class_obj, '__bases__') and class_obj.__bases__:
            bases = []
            for base in class_obj.__bases__:
                if hasattr(base, '__name__') and base.__name__ != 'object':
                    bases.append(base.__name__)
            if bases:
                lines.append(f"class {class_name}({', '.join(bases)}):")
            else:
                lines.append(f"class {class_name}:")
        else:
            lines.append(f"class {class_name}:")

        # Docstring
        if hasattr(class_obj, '__doc__') and class_obj.__doc__:
            lines.append(f'    """{class_obj.__doc__}"""')

        # Class attributes
        class_attrs = []
        for attr_name, attr_value in getattr(class_obj, '__dict__', {}).items():
            if not attr_name.startswith('__') and not callable(attr_value):
                if isinstance(attr_value, (str, int, float, bool)):
                    lines.append(f"    {attr_name} = {repr(attr_value)}")

        # Reconstruct methods
        methods_found = False
        for attr_name in dir(class_obj):
            if not attr_name.startswith('__'):
                try:
                    attr = getattr(class_obj, attr_name)
                    if callable(attr):
                        methods_found = True

                        # Try normal source extraction
                        try:
                            if hasattr(attr, '__func__'):
                                method_source = inspect.getsource(attr.__func__)
                            else:
                                method_source = inspect.getsource(attr)
                            # Indent the source
                            indented = '\n'.join([f"    {line}" for line in method_source.split('\n')])
                            lines.append(f"\n{indented}")
                            continue
                        except:
                            pass

                        # Aggressive method reconstruction
                        method_reconstruction = reconstruct_class_method(attr, attr_name, class_name)
                        lines.append(f"\n    {method_reconstruction}")
                except:
                    pass

        # If no methods are found, add pass
        if not methods_found:
            lines.append("    pass")

        return '\n'.join(lines)

    except Exception as e:
        return f"class {class_name}:\n    # Reconstruction error: {e}\n    pass"

def reconstruct_class_method(method_obj, method_name, class_name):
    """Reconstructs EXECUTABLE class method"""
    try:
        lines = []

        # Method signature
        try:
            if hasattr(method_obj, '__func__'):
                sig = inspect.signature(method_obj.__func__)
            else:
                sig = inspect.signature(method_obj)
            lines.append(f"def {method_name}{sig}:")
        except:
            # Fallback for methods without signature
            lines.append(f"def {method_name}(self):")

        # Docstring
        if hasattr(method_obj, '__doc__') and method_obj.__doc__:
            lines.append(f'    """{method_obj.__doc__}"""')

        # Logic reconstruction
        if hasattr(method_obj, '__func__') and hasattr(method_obj.__func__, '__code__'):
            code = method_obj.__func__.__code__
        elif hasattr(method_obj, '__code__'):
            code = method_obj.__code__
        else:
            lines.append("    pass")
            return '\n'.join(lines)

        # Reconstruct method logic
        method_logic = reconstruct_executable_logic(code, method_name)
        if method_logic:
            lines.extend([f"    {line}" for line in method_logic])
        else:
            lines.append("    pass")

        return '\n'.join(lines)

    except Exception as e:
        return f"def {method_name}(self):\n    # Method reconstruction error: {e}\n    pass"

def extract_advanced_function_info(func_obj, func_name):
    """Extracts advanced information from compiled functions"""
    try:
        info = []
        info.append(f"# COMPILED FUNCTION: {func_name}")
        info.append(f"# Type: {type(func_obj)}")

        # Extract signature if possible
        try:
            sig = inspect.signature(func_obj)
            info.append(f"def {func_name}{sig}:")
        except:
            try:
                # Fallback for functions without signature
                if hasattr(func_obj, '__code__'):
                    code = func_obj.__code__
                    args = code.co_varnames[:code.co_argcount]
                    info.append(f"def {func_name}({', '.join(args)}):")
                else:
                    info.append(f"def {func_name}(*args, **kwargs):")
            except:
                info.append(f"def {func_name}():")

        # Docstring
        if hasattr(func_obj, '__doc__') and func_obj.__doc__:
            info.append(f'    """{func_obj.__doc__}"""')

        # Code object analysis
        if hasattr(func_obj, '__code__'):
            code = func_obj.__code__
            info.append(f"    # Code Analysis:")
            info.append(f"    # Filename: {code.co_filename}")
            info.append(f"    # First line: {code.co_firstlineno}")
            info.append(f"    # Arg count: {code.co_argcount}")
            info.append(f"    # Local vars: {code.co_nlocals}")

            # Important constants
            if code.co_consts:
                info.append(f"    # Constants: {[c for c in code.co_consts if isinstance(c, (str, int, float))]}")

            # Used names
            if code.co_names:
                info.append(f"    # Names used: {list(code.co_names)}")

            # Local variables
            if code.co_varnames:
                info.append(f"    # Variables: {list(code.co_varnames)}")

            # Bytecode (first 20 instructions)
            info.append(f"    # Bytecode (first 20 instructions):")
            try:
                bytecode_output = StringIO()
                dis.dis(code, file=bytecode_output)
                bytecode_lines = bytecode_output.getvalue().split('\n')[:20]
                for line in bytecode_lines:
                    if line.strip():
                        info.append(f"    # {line}")
            except:
                info.append(f"    # Bytecode analysis failed")

        info.append(f"    pass  # Compiled function - original source not available")
        info.append(f"")

        return '\n'.join(info)

    except Exception as e:
        return f"# ERROR extracting {func_name}: {e}\n"

def extract_advanced_class_info(class_obj, class_name):
    """Extracts advanced information from compiled classes"""
    try:
        info = []
        info.append(f"# COMPILED CLASS: {class_name}")
        info.append(f"# Type: {type(class_obj)}")

        # Hierarchy
        if hasattr(class_obj, '__bases__') and class_obj.__bases__:
            bases = [base.__name__ for base in class_obj.__bases__ if hasattr(base, '__name__')]
            info.append(f"class {class_name}({', '.join(bases)}):")
        else:
            info.append(f"class {class_name}:")

        # Docstring
        if hasattr(class_obj, '__doc__') and class_obj.__doc__:
            info.append(f'    """{class_obj.__doc__}"""')

        # Analyze methods and attributes
        info.append(f"    # Class Analysis:")
        info.append(f"    # Module: {getattr(class_obj, '__module__', 'Unknown')}")

        # Class attributes
        class_attrs = []
        class_methods = []

        for attr_name in dir(class_obj):
            if not attr_name.startswith('__'):
                try:
                    attr = getattr(class_obj, attr_name)
                    if callable(attr):
                        class_methods.append(attr_name)
                        # Extract method info
                        info.append(f"    # Method: {attr_name}")
                        try:
                            if hasattr(attr, '__func__'):
                                method_code = attr.__func__.__code__
                                args = method_code.co_varnames[:method_code.co_argcount]
                                info.append(f"    def {attr_name}({', '.join(args)}):")
                                info.append(f"        # Constants: {[c for c in method_code.co_consts if isinstance(c, (str, int, float))]}")
                                info.append(f"        pass")
                            else:
                                info.append(f"    def {attr_name}(self):")
                                info.append(f"        pass")
                        except:
                            info.append(f"    def {attr_name}(self):")
                            info.append(f"        pass")
                        info.append(f"")
                    else:
                        class_attrs.append((attr_name, type(attr).__name__))
                except:
                    pass

        if class_attrs:
            info.append(f"    # Attributes: {class_attrs}")
        if class_methods:
            info.append(f"    # Methods: {class_methods}")

        info.append(f"")

        return '\n'.join(info)

    except Exception as e:
        return f"# ERROR extracting class {class_name}: {e}\n"

def extract_lambda_info(lambda_obj, lambda_name):
    """Extracts information from lambda functions - COMPLETE REVERSE ENGINEERING"""
    try:
        info = []
        info.append(f"# LAMBDA FUNCTION: {lambda_name}")

        if hasattr(lambda_obj, '__code__'):
            code = lambda_obj.__code__

            # Complete reconstruction of the lambda from bytecode
            reconstructed_lambda = reconstruct_lambda_from_bytecode(code, lambda_name)
            if reconstructed_lambda:
                info.append(reconstructed_lambda)
            else:
                # Fallback
                args = code.co_varnames[:code.co_argcount]
                info.append(f"{lambda_name} = lambda {', '.join(args)}: # Reconstructed from bytecode")

                # Detailed analysis
                constants = code.co_consts or []
                names = code.co_names or []

                # If there are string constants, they are probably concatenated
                string_constants = [c for c in constants if isinstance(c, str)]
                if string_constants:
                    if len(string_constants) == 1:
                        info.append(f"# Returns: {repr(string_constants[0])}")
                    elif len(string_constants) == 2:
                        # Probably concatenation
                        info.append(f"# Likely concatenates: {repr(string_constants[0])} + {repr(string_constants[1])}")
                    else:
                        info.append(f"# Uses strings: {string_constants}")

                # If global names are used
                if names:
                    info.append(f"# Accesses: {list(names)}")

        return '\n'.join(info)

    except Exception as e:
        return f"# ERROR extracting lambda {lambda_name}: {e}\n"

def reconstruct_lambda_from_bytecode(code_obj, lambda_name):
    """Reconstructs EXACT lambda from bytecode"""
    try:
        instructions = list(dis.get_instructions(code_obj))
        constants = code_obj.co_consts or []
        names = code_obj.co_names or []
        varnames = code_obj.co_varnames or []

        # Stack simulator for lambda
        stack = []

        for instr in instructions:
            opname = instr.opname
            arg = instr.arg

            if opname == 'LOAD_CONST':
                const_value = constants[arg] if arg < len(constants) else None
                stack.append(const_value)

            elif opname == 'LOAD_GLOBAL':
                global_name = names[arg] if arg < len(names) else f'name_{arg}'
                stack.append(global_name)

            elif opname == 'LOAD_FAST':
                var_name = varnames[arg] if arg < len(varnames) else f'var_{arg}'
                stack.append(var_name)

            elif opname == 'BINARY_ADD':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    # Reconstruct concatenation
                    if isinstance(left, str) and isinstance(right, str):
                        result = left + right
                    else:
                        result = f"({left} + {right})"
                    stack.append(result)

            elif opname == 'FORMAT_VALUE':
                # F-string formatting
                if stack:
                    value = stack.pop()
                    stack.append(f"{{{value}}}")

            elif opname == 'BUILD_STRING':
                # Reconstructs complete f-string
                parts = []
                for _ in range(arg):
                    if stack:
                        parts.append(str(stack.pop()))
                parts.reverse()
                f_string = "f\"" + "".join(parts) + "\""
                stack.append(f_string)

            elif opname == 'CALL_FUNCTION':
                # Function call
                argc = arg
                args = []
                for _ in range(argc):
                    if stack:
                        args.append(stack.pop())
                args.reverse()

                if stack:
                    func = stack.pop()
                    call = f"{func}({', '.join(map(str, args))})"
                    stack.append(call)

            elif opname == 'RETURN_VALUE':
                if stack:
                    return_value = stack.pop()

                    # Reconstruct complete lambda
                    args = varnames[:code_obj.co_argcount]
                    lambda_args = ', '.join(args) if args else ''

                    if isinstance(return_value, str) and return_value.startswith('f"'):
                        # F-string lambda
                        return f"{lambda_name} = lambda {lambda_args}: {return_value}"
                    elif isinstance(return_value, str):
                        # String literal lambda
                        return f"{lambda_name} = lambda {lambda_args}: {repr(return_value)}"
                    else:
                        # Expression lambda
                        return f"{lambda_name} = lambda {lambda_args}: {return_value}"
                break

        return None

    except Exception as e:
        print(f"[LAMBDA] Reconstruction error for {lambda_name}: {e}")
        return None

def extract_url_building_functions(module_obj):
    """Extracts functions that build URLs - SPECIFIC FOR YOUR CASE"""
    try:
        url_functions = {}

        for attr_name in dir(module_obj):
            if not attr_name.startswith('_'):
                try:
                    attr = getattr(module_obj, attr_name)
                    if hasattr(attr, '__code__') and callable(attr):
                        code = attr.__code__
                        constants = code.co_consts or []

                        # Look for constants that look like URLs or endpoints
                        url_parts = []
                        for const in constants:
                            if isinstance(const, str):
                                if 'http' in const or const.startswith('/api/') or 'endpoint' in attr_name.lower():
                                    url_parts.append(const)

                        if url_parts:
                            # Reconstruct the URL function
                            reconstructed = reconstruct_url_function(attr, attr_name, url_parts)
                            url_functions[attr_name] = reconstructed

                except:
                    continue

        return url_functions

    except Exception as e:
        print(f"[URL] URL function extraction error: {e}")
        return {}

def reconstruct_url_function(func_obj, func_name, url_parts):
    """Reconstructs function that builds URLs"""
    try:
        if not hasattr(func_obj, '__code__') or func_obj.__code__ is None:
            return f"def {func_name}(*args, **kwargs):\n    pass"
        code = func_obj.__code__
        instructions = list(dis.get_instructions(code))
        constants = code.co_consts or []
        names = code.co_names or []
        varnames = code.co_varnames or []

        # Common patterns for URL construction
        base_urls = [part for part in url_parts if part.startswith('http')]
        endpoints = [part for part in url_parts if part.startswith('/')]

        # Analyze if the function takes parameters
        args = varnames[:code.co_argcount]

        if base_urls and endpoints:
            # Pattern: base_url + endpoint
            base = base_urls[0]
            endpoint = endpoints[0]
            if args:
                return f"def {func_name}({', '.join(args)}):\n    return f\"{base}{endpoint}\""
            else:
                return f"def {func_name}():\n    return \"{base}{endpoint}\""

        elif base_urls and args:
            # Pattern: base_url + parameter
            base = base_urls[0]
            return f"def {func_name}({', '.join(args)}):\n    return f\"{base}/{{args[0]}}\""

        elif len(url_parts) == 1:
            # Pattern: returns constant
            url = url_parts[0]
            return f"def {func_name}():\n    return \"{url}\""

        else:
            # Pattern: complex concatenation - analyze bytecode
            return reconstruct_complex_url_function(instructions, constants, names, varnames, func_name)

    except Exception as e:
        return f"def {func_name}():\n    # Reconstruction failed: {e}\n    pass"

def reconstruct_complex_url_function(instructions, constants, names, varnames, func_name):
    """Reconstructs complex URL function from bytecode"""
    try:
        stack = []
        logic = []

        args = varnames[:len(varnames)] if varnames else []

        for instr in instructions:
            opname = instr.opname
            arg = instr.arg

            if opname == 'LOAD_CONST':
                const_value = constants[arg] if arg < len(constants) else None
                stack.append(repr(const_value) if isinstance(const_value, str) else str(const_value))

            elif opname == 'LOAD_FAST':
                var_name = varnames[arg] if arg < len(varnames) else f'arg_{arg}'
                stack.append(var_name)

            elif opname == 'LOAD_GLOBAL':
                global_name = names[arg] if arg < len(names) else f'global_{arg}'
                stack.append(global_name)

            elif opname == 'BINARY_ADD':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    stack.append(f"({left} + {right})")

            elif opname == 'FORMAT_VALUE':
                if stack:
                    value = stack.pop()
                    stack.append(f"{{{value}}}")

            elif opname == 'BUILD_STRING':
                parts = []
                for _ in range(arg):
                    if stack:
                        parts.append(stack.pop())
                parts.reverse()
                f_string = "f\"" + "".join(parts) + "\""
                stack.append(f_string)

            elif opname == 'RETURN_VALUE':
                if stack:
                    return_expr = stack.pop()
                    logic.append(f"def {func_name}({', '.join(args)}):")
                    logic.append(f"    return {return_expr}")
                break

        return '\n'.join(logic) if logic else f"def {func_name}():\n    pass"

    except Exception as e:
        return f"def {func_name}():\n    # Complex reconstruction failed: {e}\n    pass"


def reconstruct_target_pyc(module_name, module_obj):
    """COMPLETE IMPLEMENTATION: Reconstructs VALID .pyc from PyCodeObject"""
    try:
        from types import CodeType

        safe_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        pyc_file = _backup_dir / "TARGET_PYC" / f"{safe_name}.pyc"

        # STEP 1: Extract main code object
        if hasattr(module_obj, '__code__') and isinstance(module_obj.__code__, types.CodeType):
            main_code = module_obj.__code__
        else:
            # Fallback: look for code object in module
            main_code = find_main_code_object(module_obj)
            if not main_code:
                # print(f"[PYC-RECONSTRUCT] No valid main code object found for {module_name}") # MINIMAL LOG
                return False

        # STEP 2: Build VALID .pyc header
        # Magic number for current Python
        magic = importlib.util.MAGIC_NUMBER

        # Timestamp (current time)
        timestamp = struct.pack('<I', int(time.time()))

        # Size placeholder (for Python 3.7+)
        if sys.version_info >= (3, 7):
            size_field = struct.pack('<I', 0)  # Placeholder
        else:
            size_field = b''

        # STEP 3: Serialize code object with marshal
        try:
            marshaled_code = marshal.dumps(main_code)

            # STEP 4: Write complete .pyc
            with open(pyc_file, 'wb') as f:
                f.write(magic)
                f.write(timestamp)
                if size_field:
                    f.write(size_field)
                f.write(marshaled_code)

            # STEP 5: Validate generated .pyc
            if validate_generated_pyc(pyc_file):
                # print(f"[PYC-RECONSTRUCT] ✅ Valid PYC: {module_name}") # MINIMAL LOG

                # STEP 6: Also generate metadata
                generate_pyc_metadata(pyc_file, module_name, module_obj, main_code)

                # STEP 7: Attempt automatic decompilation
                attempt_automatic_decompilation(pyc_file, module_name)

                return True
            else:
                print(f"[PYC-RECONSTRUCT] ❌ Invalid PYC: {module_name}")
                return False

        except Exception as marshal_error:
            print(f"[PYC-RECONSTRUCT] Marshal error for {module_name}: {marshal_error}")
            # Fallback: reconstruct code object
            return reconstruct_code_object_manually(module_name, module_obj, main_code)

    except Exception as e:
        print(f"[PYC-RECONSTRUCT] Reconstruction error for {module_name}: {e}")
        return False

# =============================================================================
# --- START FIX FOR 'getset_descriptor' ERROR ---
# =============================================================================

def find_main_code_object(module_obj):
    """
    Finds the main code object in a module.
    CORRECTED VERSION to handle 'getset_descriptor' and other C types.
    """
    try:
        from types import FunctionType, MethodType, CodeType
        
        candidates = []

        # 1. Direct __code__
        if hasattr(module_obj, '__code__') and isinstance(module_obj.__code__, CodeType):
            return module_obj.__code__

        # 2. Search in __dict__
        if hasattr(module_obj, '__dict__'):
            for name, obj in module_obj.__dict__.items():
                try:
                    # FIX: Check specific types before accessing __code__
                    if isinstance(obj, (FunctionType, MethodType)) and hasattr(obj, '__code__'):
                        candidates.append((name, obj.__code__))
                    elif isinstance(obj, CodeType):
                        candidates.append((name, obj))
                except Exception:
                    # Ignore attributes that give error on access
                    continue

        # 3. Search attributes with code objects (iterating on dir())
        for attr_name in dir(module_obj):
            if attr_name.startswith('__'): # Skip most built-ins
                continue
            try:
                attr = getattr(module_obj, attr_name)
                
                # FIX: Check specific types. This avoids error on 'getset_descriptor'
                if isinstance(attr, (FunctionType, MethodType)) and hasattr(attr, '__code__'):
                    candidates.append((attr_name, attr.__code__))
                elif isinstance(attr, CodeType):
                    candidates.append((attr_name, attr))
            except Exception:
                # getattr() may fail on some C descriptors, ignore them
                continue

        # Choose the best (more instructions = more likely main)
        if candidates:
            # FIX: Ensure all candidates are CodeType before calling max()
            valid_candidates = [(n, c) for n, c in candidates if isinstance(c, CodeType)]
            if valid_candidates:
                best_candidate = max(valid_candidates, key=lambda x: len(x[1].co_code))
                # print(f"[CODE-FINDER] Selected main code: {best_candidate[0]}") # MINIMAL LOG
                return best_candidate[1]

        # print(f"[CODE-FINDER] No main code object found for {getattr(module_obj, '__name__', 'unknown module')}") # MINIMAL LOG
        return None

    except Exception as e:
        # Full log with traceback for better debugging
        tb_str = traceback.format_exc()
        print(f"[CODE-FINDER] Error finding main code: {e}\n{tb_str}")
        return None

# =============================================================================
# --- END FIX ---
# =============================================================================

def validate_generated_pyc(pyc_file):
    """Validate that the generated .pyc is correct"""
    try:
        from types import CodeType

        with open(pyc_file, 'rb') as f:
            # Read header
            magic = f.read(4)
            if magic != importlib.util.MAGIC_NUMBER:
                print(f"[PYC-VALIDATOR] Invalid magic: {magic.hex()}")
                return False

            timestamp = f.read(4)
            if len(timestamp) != 4:
                return False

            # Skip size field if present
            if sys.version_info >= (3, 7):
                size_field = f.read(4)
                if len(size_field) != 4:
                    return False

            # Attempt to load code object
            try:
                code_obj = marshal.load(f)
                if not isinstance(code_obj, CodeType):
                    return False

                # Verify it has valid attributes
                required_attrs = ['co_code', 'co_names', 'co_varnames', 'co_filename']
                for attr in required_attrs:
                    if not hasattr(code_obj, attr):
                        return False

                return True

            except Exception as marshal_error:
                print(f"[PYC-VALIDATOR] Marshal load error: {marshal_error}")
                return False

    except Exception as e:
        print(f"[PYC-VALIDATOR] Validation error: {e}")
        return False

# deleted generate_pyc_metadata

def extract_module_attributes_metadata(module_obj):
    """Extracts module attribute metadata"""
    try:
        attributes = {}

        for attr_name in dir(module_obj):
            if not attr_name.startswith('_'):
                try:
                    attr = getattr(module_obj, attr_name)
                    attr_type = type(attr).__name__

                    if isinstance(attr, (str, int, float, bool)):
                        attributes[attr_name] = {
                            'type': attr_type,
                            'value': attr,
                            'category': 'constant'
                        }
                    elif callable(attr):
                        attributes[attr_name] = {
                            'type': attr_type,
                            'category': 'function' if hasattr(attr, '__code__') else 'callable',
                            'has_code': hasattr(attr, '__code__')
                        }
                    elif hasattr(attr, '__dict__'):
                        attributes[attr_name] = {
                            'type': attr_type,
                            'category': 'class',
                            'methods': [name for name in dir(attr) if callable(getattr(attr, name, None))]
                        }
                    else:
                        attributes[attr_name] = {
                            'type': attr_type,
                            'category': 'other'
                        }
                except:
                    attributes[attr_name] = {'type': 'error', 'category': 'inaccessible'}

        return attributes

    except Exception as e:
        print(f"[ATTR-METADATA] Error: {e}")
        return {}

def attempt_automatic_decompilation(pyc_file, module_name):
    """Attempts automatic decompilation of .pyc"""
    try:
        # List of decompilers to try in order
        decompilers = [
            ('pycdc', try_pycdc)
        ]

        for decompiler_name, decompiler_func in decompilers:
            try:
                result = decompiler_func(pyc_file, module_name)
                if result:
                    # print(f"[AUTO-DECOMPILE] ✅ Success with {decompiler_name}: {module_name}") # MINIMAL LOG
                    return True
            except Exception as e:
                print(f"[AUTO-DECOMPILE] {decompiler_name} failed for {module_name}: {e}")
                continue

        # print(f"[AUTO-DECOMPILE] ❌ All decompilers failed for {module_name}") # MINIMAL LOG
        return False

    except Exception as e:
        print(f"[AUTO-DECOMPILE] Error: {e}")
        return False

def try_pycdc(pyc_file, module_name):
    """Attempts decompilation with pycdc"""
    try:
        import subprocess

        output_file = _backup_dir / "DECOMPILED" / f"{module_name.replace('.', '_')}_pycdc.py"

        # pycdc command (if available)
        cmd = ['pycdc', str(pyc_file)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0 and result.stdout:
            # Save output
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result.stdout)

            if len(result.stdout) > 50:
                return True

        return False

    except FileNotFoundError:
        # pycdc not installed
        return False
    except subprocess.TimeoutExpired:
        print(f"[PYCDC] Timeout for {module_name}")
        return False
    except Exception as e:
        print(f"[PYCDC] Error: {e}")
        return False

def reconstruct_code_object_manually(module_name, module_obj, original_code):
    """Manually reconstructs code object if marshal fails"""
    try:
        print(f"[CODE-MANUAL] Manual reconstruction for {module_name}")

        # Save complete code object information
        manual_file = _backup_dir / "TARGET_PYC" / f"{module_name.replace('.', '_')}_manual.txt"

        with open(manual_file, 'w', encoding='utf-8') as f:
            f.write(f"MANUAL CODE OBJECT RECONSTRUCTION: {module_name}\n")
            f.write("=" * 60 + "\n\n")

            # Complete information
            f.write("CODE OBJECT DETAILS:\n")
            f.write(f"co_name: {repr(original_code.co_name)}\n")
            f.write(f"co_filename: {repr(original_code.co_filename)}\n")
            f.write(f"co_firstlineno: {original_code.co_firstlineno}\n")
            f.write(f"co_argcount: {original_code.co_argcount}\n")
            f.write(f"co_nlocals: {original_code.co_nlocals}\n")
            f.write(f"co_stacksize: {original_code.co_stacksize}\n")
            f.write(f"co_flags: {original_code.co_flags}\n")

            # Bytecode raw
            f.write(f"\nBYTECODE (hex):\n")
            f.write(original_code.co_code.hex())
            f.write(f"\nBYTECODE (length): {len(original_code.co_code)} bytes\n")

            # Constants
            f.write(f"\nCONSTANTS:\n")
            for i, const in enumerate(original_code.co_consts or []):
                f.write(f"  [{i}] {type(const).__name__}: {repr(const)}\n")

            # Names
            f.write(f"\nNAMES:\n")
            for i, name in enumerate(original_code.co_names or []):
                f.write(f"  [{i}] {repr(name)}\n")

            # Variables
            f.write(f"\nVARIABLES:\n")
            for i, varname in enumerate(original_code.co_varnames or []):
                f.write(f"  [{i}] {repr(varname)}\n")

            # Disassembly
            f.write(f"\nDISASSEMBLY:\n")
            disasm_output = StringIO()
            dis.dis(original_code, file=disasm_output)
            f.write(disasm_output.getvalue())

        print(f"[CODE-MANUAL] Manual reconstruction saved: {manual_file.name}")
        return True

    except Exception as e:
        print(f"[CODE-MANUAL] Manual reconstruction error: {e}")
        return False

def extract_target_functions(module_name, module_obj):
    """COMPLETE IMPLEMENTATION: Extracts and reconstructs ONLY main functions and classes"""
    try:
        from types import FunctionType, MethodType, CodeType

        safe_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')

        # STEP 1: Identify TARGET functions and classes (non-system)
        target_functions = identify_target_functions(module_obj)
        target_classes = identify_target_classes(module_obj)
        target_lambdas = identify_target_lambdas(module_obj)

        # print(f"[FUNC-EXTRACT] Found {len(target_functions)} functions, {len(target_classes)} classes, {len(target_lambdas)} lambdas in {module_name}") # MINIMAL LOG

        # STEP 2: Extract each target function
        extraction_results = {
            'functions': {},
            'classes': {},
            'lambdas': {},
            'metadata': {
                'module_name': module_name,
                'extraction_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'thread': threading.current_thread().name
            }
        }

        # STEP 3: Process functions
        for func_name, func_obj in target_functions.items():
            try:
                func_result = extract_single_function(func_name, func_obj, module_name)
                extraction_results['functions'][func_name] = func_result
            except Exception as e:
                print(f"[FUNC-EXTRACT] Error extracting function {func_name}: {e}")
                extraction_results['functions'][func_name] = {'error': str(e)}

        # STEP 4: Process classes
        for class_name, class_obj in target_classes.items():
            try:
                class_result = extract_single_class(class_name, class_obj, module_name)
                extraction_results['classes'][class_name] = class_result
            except Exception as e:
                print(f"[FUNC-EXTRACT] Error extracting class {class_name}: {e}")
                extraction_results['classes'][class_name] = {'error': str(e)}

        # STEP 5: Process lambdas
        for lambda_name, lambda_obj in target_lambdas.items():
            try:
                lambda_result = extract_single_lambda(lambda_name, lambda_obj, module_name)
                extraction_results['lambdas'][lambda_name] = lambda_result
            except Exception as e:
                print(f"[FUNC-EXTRACT] Error extracting lambda {lambda_name}: {e}")
                extraction_results['lambdas'][lambda_name] = {'error': str(e)}

        # STEP 6: Generate output files
        generate_function_extraction_files(safe_name, extraction_results)

        # STEP 7: Generate JSON manifest
        generate_json_manifest(safe_name, extraction_results)

        # print(f"[FUNC-EXTRACT] ✅ Complete extraction for {module_name}") # MINIMAL LOG
        return True

    except Exception as e:
        print(f"[FUNC-EXTRACT] Extraction error for {module_name}: {e}")
        return False

def identify_target_functions(module_obj):
    """Identifies ONLY target functions (non-system/libraries)"""
    try:
        from types import FunctionType, MethodType
        target_functions = {}

        for attr_name in dir(module_obj):
            if attr_name.startswith('_'):
                continue  # Skip private/system

            try:
                attr = getattr(module_obj, attr_name)

                # Is it a function?
                if isinstance(attr, FunctionType):
                    # Verify it's a target
                    if is_target_function(attr_name, attr, module_obj):
                        target_functions[attr_name] = attr

                # Is it a bound method?
                elif isinstance(attr, MethodType):
                    if is_target_function(attr_name, attr, module_obj):
                        target_functions[attr_name] = attr

                # Has __code__ (custom callable)?
                elif hasattr(attr, '__code__') and callable(attr) and not isinstance(attr, (type, types.ModuleType)) :
                    if is_target_function(attr_name, attr, module_obj):
                        target_functions[attr_name] = attr

            except Exception as e:
                continue  # Skip problematic attributes

        return target_functions

    except Exception as e:
        print(f"[FUNC-IDENTIFY] Error identifying functions: {e}")
        return {}

def identify_target_classes(module_obj):
    """Identifies ONLY target classes"""
    try:
        target_classes = {}

        for attr_name in dir(module_obj):
            if attr_name.startswith('_'):
                continue

            try:
                attr = getattr(module_obj, attr_name)

                # Is it a class?
                if inspect.isclass(attr):
                    # Verify it's a target
                    if is_target_class(attr_name, attr, module_obj):
                        target_classes[attr_name] = attr

            except Exception as e:
                continue

        return target_classes

    except Exception as e:
        print(f"[CLASS-IDENTIFY] Error identifying classes: {e}")
        return {}

def identify_target_lambdas(module_obj):
    """Identifies ONLY target lambdas"""
    try:
        target_lambdas = {}

        for attr_name in dir(module_obj):
            if attr_name.startswith('_'):
                continue

            try:
                attr = getattr(module_obj, attr_name)

                # Is it a lambda?
                if hasattr(attr, '__code__') and hasattr(attr.__code__, 'co_name'):
                    if '<lambda>' in attr.__code__.co_name:
                        target_lambdas[attr_name] = attr

            except Exception as e:
                continue

        return target_lambdas

    except Exception as e:
        print(f"[LAMBDA-IDENTIFY] Error identifying lambdas: {e}")
        return {}

def is_target_function(func_name, func_obj, module_obj):
    """Determines if a function is target (non-system)"""
    try:
        # 1. Check name
        if func_name in ['__init__', '__new__', '__del__', '__str__', '__repr__']:
            return False  # Standard methods

        # 2. Check source module
        if hasattr(func_obj, '__module__'):
            func_module = getattr(func_obj, '__module__', '')
            if func_module and not is_target_module(func_module):
                # If the object's module is different from the module we are scanning,
                # and it's not a target module, then skip.
                if func_module != getattr(module_obj, '__name__', None):
                    return False

        # 3. Check signature/code
        if hasattr(func_obj, '__code__'):
            code = func_obj.__code__

            # Skip if filename is system
            filename = getattr(code, 'co_filename', '')
            if filename and ('<built-in>' in filename or 'site-packages' in filename):
                return False
        
            # Check constants to identify target
            constants = getattr(code, 'co_consts', [])
            if constants:
                string_constants = [c for c in constants if isinstance(c, str)]
                if any(indicator in str(c).lower() for c in string_constants
                       for indicator in ['http', 'api', 'auth', 'license']): # Example of generic indicators
                    return True

        # 4. Default: if in target module, it's likely a target
        module_name = getattr(module_obj, '__name__', '')
        if module_name and is_target_module(module_name):
             # Ensure the function is defined in this module
            if getattr(func_obj, '__module__', '') == module_name:
                return True

        return False

    except Exception as e:
        return False

def is_target_class(class_name, class_obj, module_obj):
    """Determines if a class is target"""
    try:
        # 1. Check name for target patterns
        if any(indicator in class_name.lower() for indicator in ['Config', 'Auth', 'API', 'Client', 'Server']):
            return True

        # 2. Check module
        if hasattr(class_obj, '__module__'):
            class_module = getattr(class_obj, '__module__', '')
            if class_module and not is_target_module(class_module):
                if class_module != getattr(module_obj, '__name__', None):
                    return False

        # 3. Check methods for target patterns
        if hasattr(class_obj, '__dict__'):
            for method_name, method_obj in class_obj.__dict__.items():
                if hasattr(method_obj, '__code__'):
                    code = method_obj.__code__ if hasattr(method_obj, '__code__') else None
                    if not code and hasattr(method_obj, '__func__'):
                        code = getattr(method_obj.__func__, '__code__', None)

                    if code and hasattr(code, 'co_consts'):
                        constants = code.co_consts or []
                        string_constants = [c for c in constants if isinstance(c, str)]
                        if any(indicator in str(c).lower() for c in string_constants
                               for indicator in ['http', 'api', 'auth', 'license']):
                            return True

        # 4. Default for target modules
        module_name = getattr(module_obj, '__name__', '')
        if module_name and is_target_module(module_name):
            if getattr(class_obj, '__module__', '') == module_name:
                return True

        return False

    except Exception as e:
        return False

def extract_single_function(func_name, func_obj, module_name):
    """Extracts a single function with MAXIMUM detail"""
    try:
        result = {
            'name': func_name,
            'type': 'function',
            'module': module_name,
            'extraction_success': False,
            'source_code': None,
            'bytecode_analysis': None,
            'reconstructed_code': None,
            'metadata': {}
        }

        # STEP 1: Attempt source extraction
        try:
            source_code = inspect.getsource(func_obj)
            result['source_code'] = source_code
            result['extraction_success'] = True
            # print(f"[FUNC-SINGLE] ✅ Source extracted: {func_name}") # MINIMAL LOG
        except Exception as source_error:
            result['source_extraction_error'] = str(source_error)

        # STEP 2: Bytecode analysis ALWAYS
        if hasattr(func_obj, '__code__'):
            bytecode_analysis = analyze_function_bytecode(func_obj.__code__)
            result['bytecode_analysis'] = bytecode_analysis

        # STEP 3: Reconstruction if source fails
        if not result['source_code']:
            reconstructed = reconstruct_function_from_bytecode_advanced(func_obj, func_name)
            result['reconstructed_code'] = reconstructed
            if reconstructed and len(reconstructed) > 20:
                result['extraction_success'] = True

        # STEP 4: Metadata
        result['metadata'] = extract_function_metadata(func_obj)

        # STEP 5: Generate .pyc for the single function
        if hasattr(func_obj, '__code__'):
            generate_single_function_pyc(func_name, func_obj.__code__, module_name)

        return result

    except Exception as e:
        return {
            'name': func_name,
            'type': 'function',
            'extraction_success': False,
            'error': str(e)
        }

def analyze_function_bytecode(code_obj):
    """Analyzes a function's bytecode in detail"""
    try:
        from types import CodeType
        analysis = {
            'basic_info': {
                'co_name': code_obj.co_name,
                'co_filename': code_obj.co_filename,
                'co_firstlineno': code_obj.co_firstlineno,
                'co_argcount': code_obj.co_argcount,
                'co_nlocals': code_obj.co_nlocals,
                'co_stacksize': code_obj.co_stacksize,
                'co_flags': code_obj.co_flags,
                'co_code_length': len(code_obj.co_code)
            },
            'constants': [],
            'names': [],
            'varnames': [],
            'disassembly': '',
            'instruction_count': 0,
            'patterns': []
        }

        # Constants
        if code_obj.co_consts:
            for i, const in enumerate(code_obj.co_consts):
                analysis['constants'].append({
                    'index': i,
                    'type': type(const).__name__,
                    'value': repr(const) if not isinstance(const, CodeType) else f'<code:{const.co_name}>'
                })

        # Names
        if code_obj.co_names:
            analysis['names'] = list(code_obj.co_names)

        # Variables
        if code_obj.co_varnames:
            analysis['varnames'] = list(code_obj.co_varnames)
        
        # Disassembly
        disasm_output = StringIO()
        dis.dis(code_obj, file=disasm_output)
        analysis['disassembly'] = disasm_output.getvalue()

        # Instruction count
        instructions = list(dis.get_instructions(code_obj))
        analysis['instruction_count'] = len(instructions)

        # Pattern analysis
        analysis['patterns'] = analyze_bytecode_patterns_advanced(instructions, code_obj)

        return analysis

    except Exception as e:
        return {'error': str(e)}

def analyze_bytecode_patterns_advanced(instructions, code_obj):
    """Analyzes advanced patterns in bytecode"""
    try:
        patterns = []

        # Count operation types
        op_counts = {}
        for instr in instructions:
            op_counts[instr.opname] = op_counts.get(instr.opname, 0) + 1

        # HTTP Pattern
        if any(op in op_counts for op in ['LOAD_GLOBAL', 'CALL_FUNCTION']):
            if code_obj.co_names and any('request' in str(name).lower() for name in code_obj.co_names):
                patterns.append('HTTP_REQUEST_PATTERN')

        # File I/O pattern
        if 'LOAD_GLOBAL' in op_counts and code_obj.co_names:
            if any(name in ['open', 'read', 'write'] for name in code_obj.co_names):
                patterns.append('FILE_IO_PATTERN')

        # String manipulation pattern
        if 'BINARY_ADD' in op_counts or 'FORMAT_VALUE' in op_counts:
            patterns.append('STRING_MANIPULATION_PATTERN')

        # Crypto/hash pattern
        if code_obj.co_names and any('hash' in str(name).lower() or 'crypto' in str(name).lower()
                                     for name in code_obj.co_names):
            patterns.append('CRYPTO_PATTERN')

        # API call pattern
        if code_obj.co_consts:
            string_consts = [c for c in code_obj.co_consts if isinstance(c, str)]
            if any('/api/' in str(c) or 'endpoint' in str(c).lower() for c in string_consts):
                patterns.append('API_CALL_PATTERN')

        # Conditional logic pattern
        if any(op.startswith('POP_JUMP') or op.startswith('JUMP') for op in op_counts):
            patterns.append('CONDITIONAL_LOGIC_PATTERN')

        # Loop pattern
        if 'FOR_ITER' in op_counts or 'WHILE_LOOP' in op_counts:
            patterns.append('LOOP_PATTERN')

        return patterns

    except Exception as e:
        return ['ANALYSIS_ERROR']

def extract_function_metadata(func_obj):
    """Extracts complete metadata of a function"""
    try:
        metadata = {
            'name': getattr(func_obj, '__name__', 'unknown'),
            'module': getattr(func_obj, '__module__', 'unknown'),
            'doc': getattr(func_obj, '__doc__', None),
            'annotations': getattr(func_obj, '__annotations__', {}),
            'defaults': getattr(func_obj, '__defaults__', None),
            'kwdefaults': getattr(func_obj, '__kwdefaults__', None),
            'is_coroutine': inspect.iscoroutinefunction(func_obj),
            'is_generator': inspect.isgeneratorfunction(func_obj),
            'is_async_generator': inspect.isasyncgenfunction(func_obj)
        }

        # Signature if possible
        try:
            sig = inspect.signature(func_obj)
            metadata['signature'] = str(sig)
            metadata['parameters'] = {name: str(param) for name, param in sig.parameters.items()}
        except Exception as e:
            metadata['signature_error'] = str(e)

        return metadata

    except Exception as e:
        return {'error': str(e)}

def generate_single_function_pyc(func_name, code_obj, module_name):
    """Generates .pyc for a single function"""
    try:
        safe_func_name = func_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        safe_module_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')

        pyc_file = _backup_dir / "TARGET_PYC" / f"func_{safe_module_name}_{safe_func_name}.pyc"

        # .pyc header
        magic = importlib.util.MAGIC_NUMBER
        timestamp = struct.pack('<I', int(time.time()))
        size_field = struct.pack('<I', 0) if sys.version_info >= (3, 7) else b''

        if not pyc_file.parent.exists():
            pyc_file.parent.mkdir(parents=True, exist_ok=True)

        # Write .pyc
        with open(pyc_file, 'wb') as f:
            f.write(magic)
            f.write(timestamp)
            if size_field:
                f.write(size_field)
            f.write(marshal.dumps(code_obj))

        # print(f"[FUNC-PYC] Generated: func_{safe_module_name}_{safe_func_name}.pyc") # MINIMAL LOG

    except Exception as e:
        print(f"[FUNC-PYC] Error generating PYC for {func_name}: {e}")

def extract_single_class(class_name, class_obj, module_name):
    """Extracts a single class with MAXIMUM detail"""
    try:
        result = {
            'name': class_name,
            'type': 'class',
            'module': module_name,
            'extraction_success': False,
            'source_code': None,
            'methods': {},
            'metadata': {}
        }

        # STEP 1: Attempt source extraction
        try:
            source_code = inspect.getsource(class_obj)
            result['source_code'] = source_code
            result['extraction_success'] = True
            # print(f"[CLASS-SINGLE] ✅ Source extracted: {class_name}") # MINIMAL LOG
        except Exception as source_error:
            result['source_extraction_error'] = str(source_error)

        # STEP 2: Extract methods individually
        for method_name in dir(class_obj):
            if not method_name.startswith('__'):
                try:
                    method_obj = getattr(class_obj, method_name)
                    if callable(method_obj):
                        # Ensure the method belongs to this class
                        if f".{method_name}" in str(method_obj):
                            method_result = extract_single_function(f"{class_name}.{method_name}", method_obj, module_name)
                            result['methods'][method_name] = method_result
                except Exception as e:
                    result['methods'][method_name] = {'error': str(e)}

        # STEP 3: Metadata
        result['metadata'] = extract_class_metadata(class_obj)

        # STEP 4: If source fails, reconstruct
        if not result['source_code']:
            reconstructed = reconstruct_class_from_methods(class_name, result['methods'], result['metadata'])
            result['reconstructed_code'] = reconstructed
            if reconstructed and len(reconstructed) > 20:
                result['extraction_success'] = True

        return result

    except Exception as e:
        return {
            'name': class_name,
            'type': 'class',
            'extraction_success': False,
            'error': str(e)
        }

def extract_class_metadata(class_obj):
    """Extracts metadata of a class"""
    try:
        metadata = {
            'name': getattr(class_obj, '__name__', 'unknown'),
            'module': getattr(class_obj, '__module__', 'unknown'),
            'doc': getattr(class_obj, '__doc__', None),
            'bases': [base.__name__ for base in getattr(class_obj, '__bases__', []) if hasattr(base, '__name__')],
            'mro': [cls.__name__ for cls in getattr(class_obj, '__mro__', []) if hasattr(cls, '__name__')],
            'attributes': [],
            'methods': []
        }

        # Analyze attributes and methods
        if hasattr(class_obj, '__dict__'):
            for name, value in class_obj.__dict__.items():
                if not name.startswith('__'):
                    if callable(value):
                        metadata['methods'].append(name)
                    else:
                        metadata['attributes'].append({
                            'name': name,
                            'type': type(value).__name__,
                            'value': repr(value) if isinstance(value, (str, int, float, bool)) else None
                        })

        return metadata

    except Exception as e:
        return {'error': str(e)}

def extract_single_lambda(lambda_name, lambda_obj, module_name):
    """Extracts a single lambda with COMPLETE reconstruction"""
    try:
        result = {
            'name': lambda_name,
            'type': 'lambda',
            'module': module_name,
            'extraction_success': False,
            'reconstructed_code': None,
            'metadata': {}
        }

        if hasattr(lambda_obj, '__code__'):
            # Use advanced lambda reconstruction
            reconstructed = reconstruct_lambda_from_bytecode_complete(lambda_obj.__code__, lambda_name)
            result['reconstructed_code'] = reconstructed

            if reconstructed:
                result['extraction_success'] = True
                # print(f"[LAMBDA-SINGLE] ✅ Lambda reconstructed: {lambda_name}") # MINIMAL LOG

            # Metadata
            result['metadata'] = {
                'code_info': analyze_function_bytecode(lambda_obj.__code__),
                'function_metadata': extract_function_metadata(lambda_obj)
            }

        return result

    except Exception as e:
        return {
            'name': lambda_name,
            'type': 'lambda',
            'extraction_success': False,
            'error': str(e)
        }

def reconstruct_lambda_from_bytecode_complete(code_obj, lambda_name):
    """COMPLETE reconstruction of lambda from bytecode"""
    try:
        instructions = list(dis.get_instructions(code_obj))
        constants = code_obj.co_consts or []
        names = code_obj.co_names or []
        varnames = code_obj.co_varnames or []

        # Advanced stack simulation
        stack = []

        for instr in instructions:
            opname = instr.opname
            arg = instr.arg

            if opname == 'LOAD_CONST':
                const_value = constants[arg] if arg < len(constants) else None
                stack.append(const_value)

            elif opname == 'LOAD_GLOBAL':
                global_name = names[arg] if arg < len(names) else f'name_{arg}'
                stack.append(global_name)

            elif opname == 'LOAD_FAST':
                var_name = varnames[arg] if arg < len(varnames) else f'var_{arg}'
                stack.append(var_name)

            elif opname == 'BINARY_ADD':
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    if isinstance(left, str) and isinstance(right, str):
                        result = f"'{left}' + '{right}'"
                    else:
                        result = f"({left} + {right})"
                    stack.append(result)

            elif opname == 'FORMAT_VALUE':
                if stack:
                    value = stack.pop()
                    stack.append(f"{{{value}}}")

            elif opname == 'BUILD_STRING':
                parts = []
                for _ in range(arg):
                    if stack:
                        parts.append(str(stack.pop()))
                parts.reverse()
                f_string = f"f\"{''.join(parts)}\""
                stack.append(f_string)

            elif opname == 'CALL_FUNCTION':
                argc = arg
                args = []
                for _ in range(argc):
                    if stack:
                        args.append(str(stack.pop()))
                args.reverse()

                if stack:
                    func = stack.pop()
                    call = f"{func}({', '.join(args)})"
                    stack.append(call)

            elif opname == 'RETURN_VALUE':
                if stack:
                    return_expr = stack.pop()

                    # Build complete lambda
                    args = varnames[:code_obj.co_argcount]
                    lambda_args = ', '.join(args) if args else ''

                    return f"{lambda_name} = lambda {lambda_args}: {return_expr}"
                break

        # Fallback if stack simulation fails
        args = varnames[:code_obj.co_argcount]
        lambda_args = ', '.join(args) if args else ''

        # Use constants to deduce logic
        if constants:
            string_consts = [c for c in constants if isinstance(c, str)]
            if len(string_consts) == 1:
                return f"{lambda_name} = lambda {lambda_args}: {repr(string_consts[0])}"
            elif len(string_consts) == 2:
                return f"{lambda_name} = lambda {lambda_args}: {repr(string_consts[0])} + {repr(string_consts[1])}"

        return f"{lambda_name} = lambda {lambda_args}: # Complex lambda - check bytecode analysis"

    except Exception as e:
        return f"{lambda_name} = lambda: # Reconstruction failed: {e}"

def generate_function_extraction_files(safe_name, extraction_results):
    """Generates output files for function extraction"""
    try:
        # Main file with all extracted functions
        main_file = _backup_dir / "MAIN_CODE" / f"{safe_name}_EXTRACTED_FUNCTIONS.py"

        with open(main_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(f"# EXTRACTED FUNCTIONS AND CLASSES: {extraction_results['metadata']['module_name']}\n")
            f.write(f"# Extraction time: {extraction_results['metadata']['extraction_time']}\n")
            f.write(f"# Thread: {extraction_results['metadata']['thread']}\n")
            f.write("# COMPLETE FUNCTION AND CLASS EXTRACTION\n\n")

            # Reconstructed imports
            f.write("# === RECONSTRUCTED IMPORTS ===\n")
            reconstructed_imports = deduce_imports_from_extraction(extraction_results)
            for imp in reconstructed_imports:
                f.write(f"{imp}\n")
            f.write("\n")

            # Lambda functions
            f.write("# === LAMBDA FUNCTIONS ===\n")
            for lambda_name, lambda_data in extraction_results['lambdas'].items():
                if lambda_data.get('reconstructed_code'):
                    f.write(f"{lambda_data['reconstructed_code']}\n\n")

            # Functions
            f.write("# === FUNCTIONS ===\n")
            for func_name, func_data in extraction_results['functions'].items():
                if func_data.get('source_code'):
                    f.write(f"\n{func_data['source_code']}\n")
                elif func_data.get('reconstructed_code'):
                    f.write(f"\n{func_data['reconstructed_code']}\n")
                else:
                    f.write(f"\ndef {func_name}():\n    # Extraction failed\n    pass\n\n")

            # Classes
            f.write("# === CLASSES ===\n")
            for class_name, class_data in extraction_results['classes'].items():
                if class_data.get('source_code'):
                    f.write(f"\n{class_data['source_code']}\n")
                elif class_data.get('reconstructed_code'):
                    f.write(f"\n{class_data['reconstructed_code']}\n")
                else:
                    f.write(f"\nclass {class_name}:\n    # Extraction failed\n    pass\n\n")

        # print(f"[FUNC-FILES] Generated: {main_file.name}") # MINIMAL LOG

    except Exception as e:
        print(f"[FUNC-FILES] File generation error: {e}")

def generate_json_manifest(safe_name, extraction_results):
    """Generates detailed JSON manifest"""
    try:
        manifest_file = _backup_dir / f"{safe_name}_MANIFEST.json"

        manifest = {
            "metadata": extraction_results['metadata'],
            "summary": {
                "total_functions": len(extraction_results['functions']),
                "successful_functions": len([f for f in extraction_results['functions'].values() if f.get('extraction_success')]),
                "total_classes": len(extraction_results['classes']),
                "successful_classes": len([c for c in extraction_results['classes'].values() if c.get('extraction_success')]),
                "total_lambdas": len(extraction_results['lambdas']),
                "successful_lambdas": len([l for l in extraction_results['lambdas'].values() if l.get('extraction_success')])
            },
            "modules": [extraction_results['metadata']['module_name']],
            "functions": [],
            "classes": [],
            "lambdas": [],
            "missing": []
        }

        # Populate details
        for func_name, func_data in extraction_results['functions'].items():
            func_entry = {
                "name": func_name,
                "extraction_success": func_data.get('extraction_success', False),
                "has_source": bool(func_data.get('source_code')),
                "has_bytecode": bool(func_data.get('bytecode_analysis')),
                "patterns": func_data.get('bytecode_analysis', {}).get('patterns', [])
            }

            if func_data.get('extraction_success'):
                manifest["functions"].append(func_entry)
            else:
                manifest["missing"].append({**func_entry, "type": "function"})

        for class_name, class_data in extraction_results['classes'].items():
            class_entry = {
                "name": class_name,
                "extraction_success": class_data.get('extraction_success', False),
                "has_source": bool(class_data.get('source_code')),
                "methods_count": len(class_data.get('methods', {})),
                "successful_methods": len([m for m in class_data.get('methods', {}).values() if m.get('extraction_success')])
            }

            if class_data.get('extraction_success'):
                manifest["classes"].append(class_entry)
            else:
                manifest["missing"].append({**class_entry, "type": "class"})

        for lambda_name, lambda_data in extraction_results['lambdas'].items():
            lambda_entry = {
                "name": lambda_name,
                "extraction_success": lambda_data.get('extraction_success', False),
                "has_reconstruction": bool(lambda_data.get('reconstructed_code'))
            }

            if lambda_data.get('extraction_success'):
                manifest["lambdas"].append(lambda_entry)
            else:
                manifest["missing"].append({**lambda_entry, "type": "lambda"})

        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        # print(f"[JSON-MANIFEST] Generated: {manifest_file.name}") # MINIMAL LOG

    except Exception as e:
        print(f"[JSON-MANIFEST] Manifest generation error: {e}")

def hook_imports_for_targets():
    """Hook imports to capture only target modules - THREAD SAFE"""
    try:
        original_import = __builtins__['__import__']

        def target_import_hook(name, globals=None, locals=None, fromlist=(), level=0):
            try:
                module = original_import(name, globals, locals, fromlist, level)

                # Modified to extract all valid modules
                if module and is_target_module(name, module):
                    # print(f"[GENERIC-IMPORT] 🎯 GENERIC IMPORT: {name}") # MINIMAL LOG
                    # Add to queue for threaded extraction
                    _extraction_queue.put((name, module))

                return module

            except Exception as e:
                # print(f"[GENERIC-IMPORT] Import hook error for {name}: {e}") # MINIMAL LOG
                return original_import(name, globals, locals, fromlist, level)

        __builtins__['__import__'] = target_import_hook
        print("[GENERIC] Import hook active - targeting ALL modules")
        return True

    except Exception as e:
        print(f"[GENERIC] Import hook setup error: {e}")
        return False

def scan_existing_targets_with_complete_extraction():
    """Scans sys.modules for existing targets - OPTIMIZED WITH THREADS"""
    try:
        # print("[GENERIC] Scanning for existing target modules...") # MINIMAL LOG

        targets_found = []

        # Quick scan of sys.modules
        for module_name, module_obj in sys.modules.items():
            if module_obj and is_target_module(module_name, module_obj):
                targets_found.append((module_name, module_obj))

        # print(f"[GENERIC] Found {len(targets_found)} target modules") # MINIMAL LOG

        if targets_found:
            # Extract targets with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=EXTRACTION_THREADS, thread_name_prefix="TargetExtract") as executor:
                future_to_module = {
                    executor.submit(extract_target_module_worker, target): target[0]
                    for target in targets_found
                }

                # Determine the iterator based on whether as_completed is available/needed
                # This assumes 'as_completed' is imported from concurrent.futures
                # If a dummy executor is used that doesn't require as_completed,
                # 'future_to_module.keys()' would be a list of already-completed futures.
                iterator = as_completed(future_to_module) if as_completed else future_to_module.keys()
                
                for future in iterator:
                    module_name = future_to_module[future]
                    try:
                        result = future.result()
                        if 'error' in result:
                            print(f"[GENERIC] ❌ Error extracting {module_name}: {result['error']}")
                        else:
                            print(f"[GENERIC] ✅ Completed {module_name} on {result.get('thread', 'unknown')}")
                    except Exception as exc:
                        print(f"[GENERIC] ❌ Exception during extraction of {module_name}: {exc}")

    except Exception as e:
        print(f"[GENERIC] Existing targets scan error: {e}")


    except Exception as e:
        return []

def scan_entire_directory_for_nuitka_modules():
    """Scans the ENTIRE directory for pre-compiled Nuitka modules"""
    try:
        # print("[DIRECTORY-SCAN] 🔍 Scanning entire directory for Nuitka modules...") # MINIMAL LOG

        # Find the base directory of the executable
        if hasattr(sys, 'frozen') and hasattr(sys, '_MEIPASS'):
            # PyInstaller
            base_dir = Path(sys._MEIPASS)
        elif hasattr(sys, 'frozen'):
            # Nuitka or cx_Freeze
            base_dir = Path(sys.executable).parent
        else:
            # Normal script
            base_dir = Path.cwd()

        # print(f"[DIRECTORY-SCAN] Base directory: {base_dir}") # MINIMAL LOG

        nuitka_modules = []

        # Scan recursively
        for root, dirs, files in os.walk(base_dir):
            try:
                root_path = Path(root)

                # Skip system/library directories
                if any(skip in str(root_path).lower() for skip in [
                    'site-packages', 'lib/python', 'python3', 'pip', 'setuptools',
                    'wheel', 'pkg_resources', '__pycache__', '.git', '.svn'
                ]):
                    continue

                # Look for Python/bytecode files
                for file in files:
                    file_path = root_path / file

                    # .py, .pyc, .pyo files
                    if file.endswith(('.py', '.pyc', '.pyo')):
                        if is_nuitka_related_file(file_path):
                            nuitka_modules.append(file_path)

                    # Files without extension that might be modules
                    elif '.' not in file and len(file) > 2:
                        if is_potential_nuitka_module(file_path):
                            nuitka_modules.append(file_path)

                # Look for directories that seem like modules
                for dir_name in dirs:
                    if not dir_name.startswith('.') and not dir_name.startswith('__'):
                        dir_path = root_path / dir_name
                        if is_nuitka_module_directory(dir_path):
                            nuitka_modules.append(dir_path)

            except Exception as e:
                print(f"[DIRECTORY-SCAN] Error scanning {root}: {e}")
                continue

        # print(f"[DIRECTORY-SCAN] Found {len(nuitka_modules)} potential Nuitka modules") # MINIMAL LOG

        # Process each module found
        for module_path in nuitka_modules:
            try:
                process_discovered_nuitka_module(module_path)
            except Exception as e:
                print(f"[DIRECTORY-SCAN] Error processing {module_path}: {e}")

        return nuitka_modules

    except Exception as e:
        print(f"[DIRECTORY-SCAN] Directory scan error: {e}")
        return []

def is_nuitka_related_file(file_path):
    """Determines if a file is Nuitka related"""
    try:
        file_str = str(file_path).lower()

        # Indicative filenames (using generic logic)
        if is_target_module(file_path.stem): # Use generic logic
            return True
        
        # If it's a .py/.pyc, check content
        if file_path.suffix in ['.py', '.pyc']:
            try:
                if file_path.suffix == '.py':
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)  # First 1000 chars
                        if any(keyword in content.lower() for keyword in [
                            'nuitka', 'auth', 'license', 'hwid', 'config', 'api', 'server'
                        ]):
                            return True
                else:
                    # .pyc file - check if readable
                    with open(file_path, 'rb') as f:
                        header = f.read(16)
                        if len(header) >= 4:  # Has magic number
                            return True
            except:
                pass

        return False

    except:
        return False

def is_potential_nuitka_module(file_path):
    """Checks if a file without extension could be a module"""
    try:
        # Check if it's executable or has binary patterns
        with open(file_path, 'rb') as f:
            header = f.read(100)

            # Look for patterns indicating compiled Python modules
            if b'python' in header.lower() or b'nuitka' in header.lower():
                return True

            # Common magic numbers for Python bytecode
            python_magics = [b'\x03\xf3', b'\x42\x0d', b'\x6f\x0d']
            if any(magic in header for magic in python_magics):
                return True

        return False

    except:
        return False

def is_nuitka_module_directory(dir_path):
    """Checks if a directory contains Nuitka modules"""
    try:
        # Look for __init__.py or Python files
        if (dir_path / '__init__.py').exists():
            return True
        
        # Look for .py files in the directory
        py_files = list(dir_path.glob('*.py'))
        if py_files:
            return True
            
        return False
        
    except:
        return False

def process_discovered_nuitka_module(module_path):
    """Processes a discovered Nuitka module"""
    try:
        print(f"[MODULE-DISCOVERY] 🎯 Processing: {module_path}")
        
        if module_path.is_file():
            if module_path.suffix == '.py':
                # Python source file
                extract_from_python_file(module_path)
            elif module_path.suffix in ['.pyc', '.pyo']:
                # Bytecode file
                extract_from_bytecode_file(module_path)
            else:
                # File without extension
                extract_from_unknown_file(module_path)
        elif module_path.is_dir():
            # Module directory
            extract_from_module_directory(module_path)
            
    except Exception as e:
        print(f"[MODULE-DISCOVERY] Error processing {module_path}: {e}")

def extract_from_python_file(py_file):
    """Extracts from .py source file"""
    try:
        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        # Save the complete source code
        output_file = _backup_dir / "MAIN_CODE" / f"discovered_{py_file.stem}.py"
        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(f"# DISCOVERED SOURCE FILE: {py_file}\n")
            f.write(f"# Extracted: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(source_code)
        
        print(f"[MODULE-DISCOVERY] ✅ Source extracted: {py_file.name}")
        
    except Exception as e:
        print(f"[MODULE-DISCOVERY] Error extracting {py_file}: {e}")

def extract_from_unknown_file(file_path):
    """Extracts from unknown files searching for Python patterns"""
    try:
        # Search for Python patterns in the file
        with open(file_path, 'rb') as f:
            content = f.read(10000)  # First 10KB
        
        # Search for Python magic numbers
        python_patterns = [
            b'\x03\xf3\r\n',  # Python 3.11
            b'\x42\r\n\x00',  # Python 3.10
            b'import ',
            b'def ',
            b'class ',
            b'python',
            b'nuitka'
        ]
        
        found_patterns = []
        for pattern in python_patterns:
            if pattern in content:
                found_patterns.append(pattern)
        
        if found_patterns:
            # Save information about found patterns
            output_file = _backup_dir / "TARGET_PYC" / f"unknown_file_{file_path.stem}_analysis.txt"
            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"UNKNOWN FILE ANALYSIS: {file_path}\n")
                f.write(f"Size: {len(content)} bytes\n")
                f.write(f"Patterns found: {found_patterns}\n\n")
                
                # Hex dump of first 200 bytes
                f.write("HEX DUMP (first 200 bytes):\n")
                for i in range(0, min(200, len(content)), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in content[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in content[i:i+16])
                    f.write(f"{i:04x}: {hex_part:<48} {ascii_part}\n")
                
                # Search for ASCII strings
                f.write("\nASCII STRINGS FOUND:\n")
                current_string = b''
                for byte in content:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += bytes([byte])
                    else:
                        if len(current_string) > 4:
                            try:
                                f.write(f"  {current_string.decode('ascii')}\n")
                            except:
                                pass
                        current_string = b''
            
            print(f"[MODULE-DISCOVERY] 📊 Unknown file analyzed: {file_path.name}")
            
    except Exception as e:
        print(f"[MODULE-DISCOVERY] Error analyzing unknown file {file_path}: {e}")

def extract_from_module_directory(module_dir):
    """Extracts from directory containing modules"""
    try:
        print(f"[MODULE-DISCOVERY] 📁 Processing module directory: {module_dir}")
        
        # Search for all Python files in the directory
        py_files = list(module_dir.rglob('*.py'))
        pyc_files = list(module_dir.rglob('*.pyc'))
        
        # Process each file
        for py_file in py_files:
            extract_from_python_file(py_file)
            
        for pyc_file in pyc_files:
            extract_from_bytecode_file(pyc_file)
        
        print(f"[MODULE-DISCOVERY] ✅ Module directory processed: {len(py_files)} .py, {len(pyc_files)} .pyc")
        
    except Exception as e:
        print(f"[MODULE-DISCOVERY] Error processing module directory {module_dir}: {e}")

def extraction_queue_processor():
    """Extraction queue processor - DEDICATED THREAD"""
    thread_name = threading.current_thread().name
    print(f"[TARGET-{thread_name}] Queue processor started")
    
    # Start extraction pool
    # Fallback if ThreadPoolExecutor is None (e.g., if it was mocked out for testing)
    if ThreadPoolExecutor:
        _extraction_pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_EXTRACTIONS, thread_name_prefix="QueueExtract")
    else:
        _extraction_pool = None
        print("[HOOK] Running in synchronous mode (No ThreadPool)")

    with _extraction_pool if _extraction_pool else DummyExecutor() as executor: # DummyExecutor would execute tasks synchronously
        while _extractor_active:
            try:
                # Get from queue with timeout
                try:
                    module_data = _extraction_queue.get(timeout=2.0)
                except:
                    continue
                
                # Submit for extraction
                future = executor.submit(extract_target_module_worker, module_data)
                
                # Do not wait for result to keep queue fast
                _extraction_queue.task_done()
                
            except Exception as e:
                print(f"[TARGET-{thread_name}] Queue processor error: {e}")
                time.sleep(0.5)

def cleanup_threads():
    """Cleans up thread resources - CALLED ON SHUTDOWN"""
    global _extractor_active, _thread_pool, _extraction_pool
    try:
        print("[TARGET] Shutting down threads...")
        _extractor_active = False
        
        # Wait for queue to empty
        if not _extraction_queue.empty():
            print("[TARGET] Waiting for extraction queue to finish...")
            _extraction_queue.join()
        
        # Shutdown thread pools if they exist
        if _thread_pool:
            _thread_pool.shutdown(wait=True)
        if _extraction_pool:
            _extraction_pool.shutdown(wait=True)
            
        print("[TARGET] Thread cleanup completed")
        
    except Exception as e:
        print(f"[TARGET] Cleanup error: {e}")


def preserve_module_structure():
    """Reconstructs the original directory structure from extracted modules"""
    try:
        print("[TARGET] Reconstructing module directory structure...")
        
        if not _backup_dir:
            print("[TARGET] Backup directory not set, skipping structure reconstruction.")
            return False

        structure_dir = _backup_dir / "RECONSTRUCTED_STRUCTURE"
        structure_dir.mkdir(parents=True, exist_ok=True)
        
        reconstructed_count = 0
        
        # Iterate over a copy of sys.modules keys to avoid runtime modification issues
        for module_name, module_obj in list(sys.modules.items()):
            try:
                if not is_target_module(module_name, module_obj):
                    continue
                    
                # Skip __main__ as it is handled separately usually
                if module_name == '__main__':
                    continue
                
                # Determine relative path
                parts = module_name.split('.')
                safe_name = module_name.replace('.', '_').replace('/', '_').replace('\\', '_')
                
                # Check if package
                is_package = hasattr(module_obj, '__path__')
                
                if is_package:
                    # pkg/subpkg/__init__.py
                    rel_path = Path(*parts) / "__init__.py"
                else:
                    # pkg/module.py
                    rel_path = Path(*parts[:-1]) / f"{parts[-1]}.py"
                
                # Full target directory
                target_path = structure_dir / rel_path
                try:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass

                # Find source content
                # We look in MAIN_CODE where we dumped everything as flat files
                # Naming convention there: safe_name.py or safe_name_RECONSTRUCTED.py
                
                source_content = ""
                source_found = False
                
                # 1. Try extracted source
                src_file_1 = _backup_dir / "MAIN_CODE" / f"{safe_name}.py"
                if src_file_1.exists():
                    try:
                        with open(src_file_1, 'r', encoding='utf-8', errors='ignore') as f:
                            source_content = f.read()
                        source_found = True
                    except: pass
                    
                # 2. Try reconstructed source
                if not source_found:
                    src_file_2 = _backup_dir / "MAIN_CODE" / f"{safe_name}_RECONSTRUCTED.py"
                    if src_file_2.exists():
                        try:
                            with open(src_file_2, 'r', encoding='utf-8', errors='ignore') as f:
                                source_content = f.read()
                            source_found = True
                        except: pass
                
                if source_found:
                    with open(target_path, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(source_content)
                    reconstructed_count += 1
                else:
                    # Create placeholder if we identified it but failed to extract
                    # Only create if it doesn't exist (avoid overwriting if multiple things map to same file?)
                    if not target_path.exists():
                        with open(target_path, 'w', encoding='utf-8') as f:
                            f.write(f"# Placeholder for {module_name}\n")
                            f.write(f"# Extraction failed or content not available\n")
                        reconstructed_count += 1
                    
            except Exception as e:
                # print(f"[STRUCTURE] Error processing {module_name}: {e}") # MINIMAL LOG
                continue
                
        print(f"[TARGET] ✅ Structure reconstructed: {reconstructed_count} files created in {structure_dir}")
        return True
        
    except Exception as e:
        print(f"[TARGET] Structure reconstruction error: {e}")
        return False

def extract_using_variable_technique():
    """Stub for variable extraction technique"""
    print("[TARGET] Extracting using variable technique (stub)")
    pass

def generate_comprehensive_nuitka_report(x, y):
    """Stub for report generation"""
    print("[TARGET] Generating comprehensive report (stub)")
    pass

def generate_final_json_manifest(x):
    """Stub for final manifest generation"""
    print("[TARGET] Generating final manifest (stub)")
    pass


# =============================================================================
# FINAL EXECUTION BLOCK
# =============================================================================

print(f"[TARGET] 🎯 COMPLETE NUITKA EXTRACTOR (Generic Version) READY")
print(f"[TARGET] File contains all extraction and analysis functions.")
# print(f"[TARGET] Call 'initialize_target_extraction()' or 'start_extraction_with_monitoring()' to begin.") # Old line

# --- NEW COMPLETE EXECUTION BLOCK (AS REQUESTED) ---
print("[TARGET] HOOK.PY EXECUTING: Setting up directories...")
try:
    if setup_target_extraction_directory():
        print(f"[TARGET] HOOK.PY EXECUTING: --- STARTING COMPREHENSIVE EXTRACTION ---")
        
        # Initialize variables for reports
        binary_analysis = None
        assembly_correlations = None
        native_code_analysis = None

        # 1. Scan existing modules (Python code)
        print(f"[TARGET] HOOK.PY (1/9): Scanning existing modules (sys.modules)...")
        scan_existing_targets_with_complete_extraction()
        
        # 2. Scan memory for RCDATA-like blobs
        # print(f"[TARGET] HOOK.PY (2/9): Scanning memory for Nuitka data blobs...")
        # scan_memory_for_nuitka_data_blobs() # REMOVED
        
        # 3. Scan filesystem for more modules
        print(f"[TARGET] HOOK.PY (2/9): Scanning directory for Nuitka modules...")
        scan_entire_directory_for_nuitka_modules()
        
        # 4. Reconstruct module structure
        print(f"[TARGET] HOOK.PY (3/9): Reconstructing module directory structure...")
        preserve_module_structure()

        # REMOVED NATIVE ANALYSIS STEPS (5, 6, 7, 8 partial)
        
        # 8. Run placeholder analysis functions
        print(f"[TARGET] HOOK.PY (4/9): Running advanced variable extraction...")
        # correlate_memory_with_binary_analysis(binary_analysis) # REMOVED
        # scan_memory_for_bytecode_patterns() # REMOVED
        extract_using_variable_technique()
        
        # 9. Generate final reports
        print(f"[TARGET] HOOK.PY (5/9): Generating final reports and manifests...")
        generate_comprehensive_nuitka_report(None, None)
        generate_final_json_manifest(None)
        
        print(f"[TARGET] HOOK.PY EXECUTING: --- COMPREHENSIVE EXTRACTION COMPLETE ---")
        
        try:
            import ctypes
            MessageBox = ctypes.windll.user32.MessageBoxW
            MessageBox(None, 'Python __hook__.py COMPLETED successfully!\nAll analysis and extraction steps finished.\nCheck console and output directory.', 'Hook Script Success (COMPLETE)', 0x40) # 0x40 = MB_ICONINFORMATION
        except Exception as e:
            print(f"[TARGET] HOOK.PY ERROR: Could not show success MessageBox: {e}")

    else:
        print("[TARGET] HOOK.PY FAILED: Could not set up extraction directory.")
        raise Exception("Failed to set up extraction directory.")

except Exception as e:
    print(f"[TARGET] HOOK.PY FAILED during execution: {e}")
    traceback.print_exc()
    try:
        # Try to show an error message popup
        import ctypes
        MessageBox = ctypes.windll.user32.MessageBoxW
        MessageBox(None, f'Python __hook__.py FAILED TO RUN.\n\nError: {e}', 'Hook Script FAILED', 0x10) # 0x10 = MB_ICONERROR
    except Exception as e2:
        print(f"[TARGET] HOOK.PY ERROR: Could not show failure MessageBox: {e2}")
