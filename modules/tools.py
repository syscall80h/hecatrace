from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger("hecatrace.tools")

DEFAULT_TOOLS_PATH = Path("/opt/hecatrace/config/tools.yaml")

# Types that point to resources (not executables)
_RESOURCE_TYPES = {"directory", "file"}


class ToolRegistry:
    """
    Loads tools.yaml and resolves tool paths inside the container.

    Usage:
        registry = ToolRegistry.load()
        cmd = registry.cmd_list("regripper") + ["-r", hive, "-a"]
        cwd = registry.cwd("regripper")
    """

    def __init__(self, tools: dict):
        self._tools = tools

    @classmethod
    def load(cls, path: Path = DEFAULT_TOOLS_PATH) -> "ToolRegistry":
        if not path.is_file():
            log.warning("tools.yaml not found at %s — empty registry.", path)
            return cls({})
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(data.get("tools", {}))

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def command(self, name: str) -> str:
        """Returns the raw command (path or name on PATH)."""
        tool = self._tools.get(name)
        if not tool:
            raise KeyError(f"Unknown tool in registry: {name!r}")
        return tool["command"]

    def path(self, name: str) -> Path:
        """Returns the Path of the command or resource."""
        return Path(self.command(name))

    def cwd(self, name: str) -> Optional[Path]:
        """Returns the required working directory, or None."""
        tool = self._tools.get(name)
        if not tool:
            return None
        cwd = tool.get("cwd")
        return Path(cwd) if cwd else None

    def cmd_list(self, name: str) -> list[str]:
        """
        Returns the command as a list for subprocess.
        Python and Perl scripts are prefixed with their interpreter.
        """
        tool = self._tools.get(name)
        if not tool:
            raise KeyError(f"Unknown tool in registry: {name!r}")
        command = tool["command"]
        tool_type = tool.get("type", "binary")
        if tool_type == "python":
            return ["python3", command]
        if tool_type == "perl":
            return ["perl", command]
        return [command]

    def is_optional(self, name: str) -> bool:
        tool = self._tools.get(name)
        return bool(tool.get("optional", False)) if tool else True

    def has(self, name: str) -> bool:
        """Checks whether a tool is available (present in the registry AND accessible)."""
        if name not in self._tools:
            return False
        return self._is_available(name)

    # ------------------------------------------------------------------
    # Startup check
    # ------------------------------------------------------------------

    def check_all(self) -> tuple[list[str], list[str]]:
        """
        Checks the presence of all tools in the registry.
        Returns (missing_required, missing_optional).
        """
        missing_required: list[str] = []
        missing_optional: list[str] = []

        for name in self._tools:
            if not self._is_available(name):
                if self.is_optional(name):
                    missing_optional.append(name)
                else:
                    missing_required.append(name)

        return missing_required, missing_optional

    def _is_available(self, name: str) -> bool:
        tool = self._tools[name]
        command = tool.get("command", "")
        tool_type = tool.get("type", "binary")

        if tool_type == "directory":
            return Path(command).is_dir()
        if tool_type == "file":
            return Path(command).is_file()

        p = Path(command)
        if p.is_absolute():
            return p.exists()
        return shutil.which(command) is not None
