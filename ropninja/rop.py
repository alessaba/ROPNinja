"""
ROP gadget discovery and display helpers.
"""

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from binaryninja import BinaryView
from binaryninja.enums import InstructionTextTokenType, SectionSemantics
from binaryninja.settings import Settings


PLUGIN_NAME = "ROPNinja"
SETTING_MAX_PREVIOUS_BYTES = "ropninja.maxPreviousBytes"
SETTING_DEDUPLICATE_GADGETS = "ropninja.deduplicateGadgets"
SETTING_INCLUDE_BRANCHES = "ropninja.includeBranches"
SETTING_INCLUDE_LEAVE = "ropninja.includeLeave"
SETTING_STRIP_ADDRESS_ZEROS = "ropninja.stripAddressZeros"
SETTING_AUTO_FIND_ON_OPEN = "ropninja.autoFindOnOpen"
DEFAULT_MAX_PREVIOUS_BYTES = 32

_RET_INSTRS = {"retn": [b"\xc3", b"\xf2\xc3"], "retf": [b"\xcb"]}
_RET_MNEMONICS = {"ret", "retn", "retf"}


@dataclass
class GadgetInstruction:
    address: int
    length: int
    text: str
    fragments: list[tuple[Any, str]]


@dataclass
class ROPGadget:
    rva: int
    instructions: list[GadgetInstruction]

    @property
    def text(self) -> str:
        return " ; ".join(instr.text for instr in self.instructions)

    @property
    def fragments(self) -> list[tuple[Any, str]]:
        result: list[tuple[Any, str]] = []
        for index, instr in enumerate(self.instructions):
            if index:
                result.append((InstructionTextTokenType.TextToken, " ; "))
            result.extend(instr.fragments)
        return result


@dataclass
class GadgetDisplayRow:
    address: int
    text: str
    fragments: list[tuple[Any, str]]


def register_plugin_settings() -> None:
    settings = Settings()
    settings.register_group(PLUGIN_NAME, PLUGIN_NAME)
    settings.register_setting(
        SETTING_MAX_PREVIOUS_BYTES,
        json.dumps(
            {
                "title": "Maximum Gadget Backtrack",
                "description": "Maximum number of bytes to walk backwards from a return instruction while building ROP gadgets.",
                "type": "number",
                "default": DEFAULT_MAX_PREVIOUS_BYTES,
                "minValue": 1,
                "maxValue": 256,
            }
        ),
    )
    settings.register_setting(
        SETTING_DEDUPLICATE_GADGETS,
        json.dumps(
            {
                "title": "Deduplicate Gadgets",
                "description": "Show only the first instance of gadgets with identical instruction text.",
                "type": "boolean",
                "default": True,
            }
        ),
    )
    settings.register_setting(
        SETTING_INCLUDE_BRANCHES,
        json.dumps(
            {
                "title": "Include Jump Gadgets",
                "description": "Include gadgets containing jmp or conditional-jump instructions. These can be useful for JOP or special-purpose chains but add noise to ordinary ROP searches.",
                "type": "boolean",
                "default": False,
            }
        ),
    )
    settings.register_setting(
        SETTING_INCLUDE_LEAVE,
        json.dumps(
            {
                "title": "Include Leave Gadgets",
                "description": "Include gadgets containing leave instructions. These are often stack-pivot gadgets but are disabled by default to preserve the plugin's historical filtering behavior.",
                "type": "boolean",
                "default": False,
            }
        ),
    )
    settings.register_setting(
        SETTING_STRIP_ADDRESS_ZEROS,
        json.dumps(
            {
                "title": "Strip Leading Address Zeros",
                "description": "Display gadget addresses without fixed-width leading zeros in the sidebar table.",
                "type": "boolean",
                "default": False,
            }
        ),
    )
    settings.register_setting(
        SETTING_AUTO_FIND_ON_OPEN,
        json.dumps(
            {
                "title": "Auto-Find When UI Opens",
                "description": "Automatically search for ROP gadgets when the ROPNinja sidebar or split pane is shown.",
                "type": "boolean",
                "default": False,
            }
        ),
    )


def get_max_previous_bytes(bv: BinaryView | None = None) -> int:
    try:
        value = Settings().get_integer(SETTING_MAX_PREVIOUS_BYTES, bv)
    except Exception:
        value = DEFAULT_MAX_PREVIOUS_BYTES
    return max(1, int(value or DEFAULT_MAX_PREVIOUS_BYTES))


def get_deduplicate_gadgets(bv: BinaryView | None = None) -> bool:
    try:
        return Settings().get_bool(SETTING_DEDUPLICATE_GADGETS, bv)
    except Exception:
        return True


def get_include_branches(bv: BinaryView | None = None) -> bool:
    try:
        return Settings().get_bool(SETTING_INCLUDE_BRANCHES, bv)
    except Exception:
        return False


def get_include_leave(bv: BinaryView | None = None) -> bool:
    try:
        return Settings().get_bool(SETTING_INCLUDE_LEAVE, bv)
    except Exception:
        return False


def get_strip_address_zeros(bv: BinaryView | None = None) -> bool:
    try:
        return Settings().get_bool(SETTING_STRIP_ADDRESS_ZEROS, bv)
    except Exception:
        return False


def get_auto_find_on_open(bv: BinaryView | None = None) -> bool:
    try:
        return Settings().get_bool(SETTING_AUTO_FIND_ON_OPEN, bv)
    except Exception:
        return False


def _normalize_gadget(gadget: str) -> str:
    return " ".join(gadget.split())


def _gadget_text(gadget: str | ROPGadget) -> str:
    return gadget.text if isinstance(gadget, ROPGadget) else gadget


def _gadget_fragments(gadget: str | ROPGadget) -> list[tuple[Any, str]]:
    if isinstance(gadget, ROPGadget):
        return gadget.fragments
    return [(InstructionTextTokenType.TextToken, gadget)]


def _compact_token_fragments(tokens) -> list[tuple[Any, str]]:
    fragments: list[tuple[Any, str]] = []
    for token in tokens:
        for part in re.split(r"(\s+)", token.text):
            if not part:
                continue
            if part.isspace():
                if fragments and not fragments[-1][1].endswith(" "):
                    fragments.append((InstructionTextTokenType.TextToken, " "))
                continue
            fragments.append((token.type, part))

    while fragments and fragments[-1][1].isspace():
        fragments.pop()

    return fragments


def format_gadgets_for_display(
    bv: BinaryView,
    gadgets: dict[int, str | ROPGadget],
    deduplicate: bool | None = None,
) -> list[tuple[int, str]]:
    return [
        (row.address, row.text)
        for row in format_gadget_rows_for_display(bv, gadgets, deduplicate)
    ]


def format_gadget_rows_for_display(
    bv: BinaryView,
    gadgets: dict[int, str | ROPGadget],
    deduplicate: bool | None = None,
) -> list[GadgetDisplayRow]:
    if deduplicate is None:
        deduplicate = get_deduplicate_gadgets(bv)

    rows: list[GadgetDisplayRow] = []
    seen: set[str] = set()
    for rva, gadget in sorted(gadgets.items()):
        gadget_text = _normalize_gadget(_gadget_text(gadget))
        if deduplicate and gadget_text in seen:
            continue
        seen.add(gadget_text)
        rows.append(GadgetDisplayRow(rva + bv.start, gadget_text, _gadget_fragments(gadget)))
    return rows


class ROPGadgetFinder:
    """
    Locate ROP gadgets in executable BinaryViews.
    """

    def __init__(
        self,
        bv: BinaryView,
        max_previous_bytes: int | None = None,
        include_branches: bool | None = None,
        include_leave: bool | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ):
        self.bv = bv
        self.max_previous_bytes = max_previous_bytes or get_max_previous_bytes(bv)
        self.include_branches = get_include_branches(bv) if include_branches is None else include_branches
        self.include_leave = get_include_leave(bv) if include_leave is None else include_leave
        self.should_cancel = should_cancel
        self._instruction_cache: dict[int, GadgetInstruction | None] = {}

    def find_gadgets(self) -> dict[int, ROPGadget]:
        if not self.bv.executable:
            return {}

        ranges = self._candidate_ranges()
        if not ranges:
            return {}

        return self._find_gadgets_in_ranges(ranges)

    def _cancelled(self) -> bool:
        return bool(self.should_cancel and self.should_cancel())

    @staticmethod
    def _object_range(value) -> tuple[int, int] | None:
        start = getattr(value, "start", None)
        end = getattr(value, "end", None)
        if start is None or end is None:
            return None
        start = int(start)
        end = int(end)
        if end <= start:
            return None
        return (start, end)

    @staticmethod
    def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        return merged

    def _candidate_ranges(self) -> list[tuple[int, int]]:
        ranges = self._executable_segment_ranges()
        if ranges:
            return self._merge_ranges(ranges)

        ranges = self._code_section_ranges()
        if ranges:
            return self._merge_ranges(ranges)

        ranges = self._function_block_ranges()
        if ranges:
            return self._merge_ranges(ranges)

        return self._instruction_range_fallback()

    def _executable_segment_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        try:
            segments = self.bv.segments
        except Exception:
            return ranges

        for segment in segments:
            if not segment.executable:
                continue
            segment_range = self._object_range(segment)
            if segment_range is not None:
                ranges.append(segment_range)
        return ranges

    def _code_section_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        try:
            sections = self.bv.sections.values()
        except Exception:
            return ranges

        for section in sections:
            if section.semantics != SectionSemantics.ReadOnlyCodeSectionSemantics:
                continue
            section_range = self._object_range(section)
            if section_range is not None:
                ranges.append(section_range)
        return ranges

    def _function_block_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        try:
            functions = self.bv.functions
        except Exception:
            return ranges

        for function in functions:
            if self._cancelled():
                return ranges
            for block in function.basic_blocks:
                block_range = self._object_range(block)
                if block_range is not None:
                    ranges.append(block_range)
        return ranges

    def _instruction_range_fallback(self) -> list[tuple[int, int]]:
        first_addr = None
        last_addr = None
        for _, addr in self.bv.instructions:
            if self._cancelled():
                return []
            if first_addr is None:
                first_addr = addr
            last_addr = addr

        if first_addr is None or last_addr is None:
            return []

        end = last_addr + (self.bv.arch.max_instr_length if self.bv.arch is not None else 1)
        return [(first_addr, end)]

    def _decode_instruction(self, addr: int) -> GadgetInstruction | None:
        if addr in self._instruction_cache:
            return self._instruction_cache[addr]

        if self.bv.arch is None:
            self._instruction_cache[addr] = None
            return None

        tokens, length = self.bv.arch.get_instruction_text(
            self.bv.read(addr, self.bv.arch.max_instr_length),
            addr,
        )
        if tokens is None or length <= 0:
            self._instruction_cache[addr] = None
            return None

        fragments = _compact_token_fragments(tokens)
        text = "".join(text for _, text in fragments).strip()
        if not text:
            self._instruction_cache[addr] = None
            return None

        instruction = GadgetInstruction(addr, length, text, fragments)
        self._instruction_cache[addr] = instruction
        return instruction

    def _disas_all_instrs(self, start_addr: int, ret_addr: int) -> list[GadgetInstruction] | None:
        instructions: list[GadgetInstruction] = []
        curr_addr = start_addr
        while curr_addr < ret_addr:
            if self._cancelled():
                return None

            instruction = self._decode_instruction(curr_addr)
            if instruction is None:
                return None

            mnemonic = instruction.text.split(maxsplit=1)[0].lower().rstrip(":")
            if not self.include_branches and mnemonic.startswith("j"):
                return None
            if not self.include_leave and mnemonic == "leave":
                return None
            if mnemonic in _RET_MNEMONICS:
                return None

            instructions.append(instruction)
            curr_addr += instruction.length

        if curr_addr != ret_addr:
            return None

        return instructions

    def _calculate_gadget_from_ret(
        self,
        gadgets: dict[int, ROPGadget],
        ret_addr: int,
        range_start: int,
    ) -> dict[int, ROPGadget]:
        ret_instr = self._decode_instruction(ret_addr)
        if ret_instr is None:
            return gadgets

        start_addr = max(range_start, ret_addr - self.max_previous_bytes)
        for gadget_addr in range(start_addr, ret_addr + 1):
            if self._cancelled():
                break

            instructions = self._disas_all_instrs(gadget_addr, ret_addr)
            if instructions is None:
                continue

            gadget_rva = gadget_addr - self.bv.start
            gadgets[gadget_rva] = ROPGadget(gadget_rva, [*instructions, ret_instr])
        return gadgets

    def _find_gadgets_in_ranges(self, ranges: list[tuple[int, int]]) -> dict[int, ROPGadget]:
        gadgets: dict[int, ROPGadget] = {}
        ret_addrs: dict[int, int] = {}

        for range_start, range_end in ranges:
            if self._cancelled():
                return gadgets

            for bytecodes in _RET_INSTRS.values():
                for bytecode in bytecodes:
                    next_start = range_start
                    while next_start < range_end:
                        if self._cancelled():
                            return gadgets

                        next_ret_addr = self.bv.find_next_data(next_start, bytecode)
                        if next_ret_addr is None or next_ret_addr >= range_end:
                            break
                        if next_ret_addr + len(bytecode) <= range_end:
                            ret_addrs[next_ret_addr] = range_start
                        next_start = next_ret_addr + 1

        for ret_addr, range_start in sorted(ret_addrs.items()):
            if self._cancelled():
                break
            gadgets = self._calculate_gadget_from_ret(gadgets, ret_addr, range_start)

        return gadgets


def find_rop_gadgets_in_view(
    bv: BinaryView,
    max_previous_bytes: int | None = None,
    include_branches: bool | None = None,
    include_leave: bool | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[int, ROPGadget]:
    return ROPGadgetFinder(
        bv,
        max_previous_bytes,
        include_branches,
        include_leave,
        should_cancel,
    ).find_gadgets()
