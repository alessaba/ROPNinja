"""
A minimal stand-in for the Binary Ninja Python API, registered as ``binaryninja``.

ROPNinja imports Binary Ninja at module import time, and tests must run without a
Binary Ninja install. Importing this module installs the stubs: only the surface the
plugin touches is implemented, and ``Settings`` behaves like Binary Ninja's global
registration store, so registered defaults are what the finder reads.

Importing this module also puts the repository root on ``sys.path``, so the tests can
import ``ropninja`` no matter which directory the test runner starts from.
"""

import json
import os
import sys
import types
from typing import ClassVar

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class InstructionTextTokenType:
    TextToken = 0
    InstructionToken = 1
    OperandSeparatorToken = 2
    RegisterToken = 3
    IntegerToken = 4
    PossibleAddressToken = 5


class SectionSemantics:
    DefaultSectionSemantics = 0
    ReadOnlyCodeSectionSemantics = 1
    ReadOnlyDataSectionSemantics = 2


class SettingsScope:
    SettingsUserScope = 0


class Settings:
    """Global settings store with registered defaults, like Binary Ninja's."""

    _registered: ClassVar[dict] = {}
    _values: ClassVar[dict] = {}

    def register_group(self, name, title) -> None:
        pass

    def register_setting(self, name, value) -> None:
        try:
            self._registered[name] = json.loads(value)
        except (TypeError, ValueError):
            self._registered[name] = {"default": value}

    def get_bool(self, name, view=None) -> bool:
        return bool(self._value(name, False))

    def get_integer(self, name, view=None) -> int:
        return int(self._value(name, 0))

    def get_string(self, name, view=None) -> str:
        return str(self._value(name, ""))

    def set_bool(self, name, value, scope=None) -> None:
        self._values[name] = bool(value)

    def set_integer(self, name, value, scope=None) -> None:
        self._values[name] = int(value)

    def set_string(self, name, value, scope=None) -> None:
        self._values[name] = str(value)

    def _value(self, name, fallback):
        if name in self._values:
            return self._values[name]
        return self._registered.get(name, {}).get("default", fallback)


class BinaryView:
    """Placeholder for type annotations."""


class BackgroundTaskThread:
    """Placeholder; the sidebar UI that subclasses it is skipped in tests."""


def core_ui_enabled() -> bool:
    """Tests never load the Binary Ninja UI."""
    return False


def log_error(message, *args) -> None:
    pass


def install() -> None:
    """Register the stub modules, unless something already provided them."""
    if "binaryninja" in sys.modules:
        return

    binaryninja = types.ModuleType("binaryninja")
    binaryninja.BinaryView = BinaryView
    binaryninja.core_ui_enabled = core_ui_enabled
    binaryninja.log_error = log_error

    enums = types.ModuleType("binaryninja.enums")
    enums.InstructionTextTokenType = InstructionTextTokenType
    enums.SectionSemantics = SectionSemantics
    enums.SettingsScope = SettingsScope

    settings = types.ModuleType("binaryninja.settings")
    settings.Settings = Settings

    plugin = types.ModuleType("binaryninja.plugin")
    plugin.BackgroundTaskThread = BackgroundTaskThread

    binaryninja.enums = enums
    binaryninja.settings = settings
    binaryninja.plugin = plugin

    sys.modules["binaryninja"] = binaryninja
    sys.modules["binaryninja.enums"] = enums
    sys.modules["binaryninja.settings"] = settings
    sys.modules["binaryninja.plugin"] = plugin


install()

TokenType = InstructionTextTokenType
