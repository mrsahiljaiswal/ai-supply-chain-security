"""Callable rules for the static pickle scan.

Severity is not decided here. This module only classifies a (module, name)
pair as dangerous, safe, or unknown. The policy file supplies severity.
"""

Classification = str  # "dangerous" | "safe" | "unknown"

# Whole modules: any attribute can run code or touch the system.
# posix and nt are the os implementation modules (same capability as os).
# _io.open is the implementation behind io.open.
DENY_MODULES = frozenset({
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "shutil",
    "socket",
    "pathlib",
    "ctypes",
    "pty",
    "importlib",
    "pickle",
    "marshal",
    "torch.serialization",
})

_BUILTIN_DENY = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "getattr",
    "breakpoint",
    "open",
})

DENY_NAMES = {
    "builtins": _BUILTIN_DENY,
    "__builtin__": _BUILTIN_DENY,
    "io": frozenset({"open"}),
    "_io": frozenset({"open"}),
    "operator": frozenset({"methodcaller"}),
}

# Tensor rebuild helpers the scanner must not treat as critical.
SAFE_EXACT = frozenset({
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch", "FloatStorage"),
    ("collections", "OrderedDict"),
})

NUMPY_RECONSTRUCTORS = frozenset({
    "_reconstruct",
    "scalar",
    "dtype",
    "ndarray",
    "_frombuffer",
})


def _denied_module(module: str) -> bool:
    return any(module == denied or module.startswith(denied + ".") for denied in DENY_MODULES)


def _numpy_reconstructor(module: str, name: str) -> bool:
    if module != "numpy" and not module.startswith("numpy."):
        return False
    return name in NUMPY_RECONSTRUCTORS


def classify_callable(module: str, name: str) -> Classification:
    """Classify one resolved global. Never imports the named module."""
    module = module.strip()
    name = name.strip()
    if not module or not name:
        return "unknown"
    if _denied_module(module) or name in DENY_NAMES.get(module, ()):
        return "dangerous"
    if (module, name) in SAFE_EXACT or _numpy_reconstructor(module, name):
        return "safe"
    return "unknown"
