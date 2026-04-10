"""
utils/ffmpeg.py

Finds the ffmpeg binary across all common install locations on
Windows, macOS, and Linux — including package managers that do NOT
add themselves to PATH automatically (WinGet, Scoop, Chocolatey, Homebrew).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from functools import lru_cache


@lru_cache(maxsize=1)
def find_ffmpeg() -> str:
    """
    Return the absolute path to the ffmpeg executable.

    Search order:
      1. PATH (shutil.which) — covers any properly-installed ffmpeg
      2. Windows-specific locations (WinGet, Scoop, Chocolatey, manual)
      3. macOS Homebrew (Apple Silicon and Intel)
      4. Common Linux paths

    Raises RuntimeError if ffmpeg cannot be found anywhere.
    """
    # 1. Standard PATH lookup
    found = shutil.which("ffmpeg")
    if found:
        return found

    candidates: list[Path] = []

    if sys.platform == "win32" or os.name == "nt":
        home = Path.home()
        candidates += [
            # WinGet (glob for any version subfolder)
            *sorted(
                (home / "AppData/Local/Microsoft/WinGet/Packages").glob(
                    "Gyan.FFmpeg*/*/bin/ffmpeg.exe"
                ),
                reverse=True,   # newest version first
            ),
            # WinGet symlink directory
            home / "AppData/Local/Microsoft/WinGet/Links/ffmpeg.exe",
            # Scoop
            home / "scoop/apps/ffmpeg/current/bin/ffmpeg.exe",
            # Chocolatey
            Path("C:/ProgramData/chocolatey/bin/ffmpeg.exe"),
            # Common manual installs
            Path("C:/ffmpeg/bin/ffmpeg.exe"),
            Path("C:/Program Files/ffmpeg/bin/ffmpeg.exe"),
            Path("C:/Program Files (x86)/ffmpeg/bin/ffmpeg.exe"),
        ]
    elif sys.platform == "darwin":
        candidates += [
            Path("/opt/homebrew/bin/ffmpeg"),    # Apple Silicon
            Path("/usr/local/bin/ffmpeg"),       # Intel Homebrew
        ]
    else:
        candidates += [
            Path("/usr/bin/ffmpeg"),
            Path("/usr/local/bin/ffmpeg"),
            Path("/snap/bin/ffmpeg"),
        ]

    for path in candidates:
        if path.is_file():
            return str(path)

    raise RuntimeError(
        "ffmpeg not found on PATH or in any common install location.\n"
        "Install it and ensure it is accessible:\n"
        "  Windows : winget install ffmpeg  (then restart your terminal)\n"
        "  macOS   : brew install ffmpeg\n"
        "  Linux   : sudo apt install ffmpeg\n"
        f"Searched: {[str(c) for c in candidates[:5]]} …"
    )
