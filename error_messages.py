"""Stable English summaries for errors shown by Drive Cleanr."""


_WINDOWS_ERROR_MESSAGES = {
    2: "The file was not found",
    3: "The path was not found",
    5: "Access was denied",
    32: "The file is in use by another process",
    33: "The file is locked by another process",
    112: "The destination drive is out of space",
}

_OS_ERROR_MESSAGES = {
    2: "The file or path was not found",
    13: "Access was denied",
    17: "The file or path already exists",
    20: "A path component is not a directory",
    21: "A path component is a directory, not a file",
    28: "The destination drive is out of space",
    30: "The destination is read-only",
    16: "The file is in use or unavailable",
}


def safe_terminal_text(value, fallback="Unknown"):
    """Escape non-printing text before showing untrusted values in a terminal."""
    if value is None:
        value = fallback
    escaped = []
    for character in str(value):
        if character.isprintable():
            escaped.append(character)
            continue
        codepoint = ord(character)
        if codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def describe_error(error):
    """Describe an exception without exposing locale-dependent OS text."""
    if not isinstance(error, OSError):
        message = str(error).strip()
        return safe_terminal_text(message or type(error).__name__)

    windows_code = getattr(error, "winerror", None)
    if windows_code is not None:
        message = _WINDOWS_ERROR_MESSAGES.get(windows_code)
        if message:
            return f"{message} (Windows error {windows_code})"
        return f"Operating-system error (Windows error {windows_code})"

    os_code = getattr(error, "errno", None)
    if os_code is not None:
        message = _OS_ERROR_MESSAGES.get(os_code)
        if not message:
            message = "Operating-system error"
        return f"{message} (error code {os_code})"

    if isinstance(error, PermissionError):
        return "Access was denied"
    if isinstance(error, FileNotFoundError):
        return "The file or path was not found"
    if isinstance(error, FileExistsError):
        return "The file or path already exists"
    if isinstance(error, NotADirectoryError):
        return "A path component is not a directory"
    if isinstance(error, IsADirectoryError):
        return "A path component is a directory, not a file"
    if isinstance(error, TimeoutError):
        return "The operation timed out"
    return "Operating-system error"
