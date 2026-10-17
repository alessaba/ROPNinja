"""
Architecture-specific ROP gadget knowledge.

The finder in :mod:`ropninja.rop` keeps the scanning control flow architecture
independent. Everything that depends on the instruction set lives in a profile:
which encodings may end a gadget, how instruction addresses are aligned, which
interior instructions invalidate a gadget window, and how gadgets map onto the
sidebar categories.
"""

import re
from collections.abc import Iterator
from typing import ClassVar, Protocol

from binaryninja import BinaryView


class DecodedInstruction(Protocol):
    """The parts of a decoded instruction that architecture rules need."""

    text: str
    mnemonic: str


class ArchProfile:
    """Gadget recognition rules for one architecture."""

    #: Instruction fetch granularity: valid gadget starts are aligned to this many bytes.
    alignment = 1
    #: Mnemonics that always invalidate a gadget window when found before a terminator.
    return_mnemonics: frozenset[str] = frozenset()

    #: Sidebar category name -> lowercase regex matched against gadget text.
    category_patterns: ClassVar[dict[str, re.Pattern[str]]] = {}

    def terminator_candidates(
        self,
        bv: BinaryView,
        range_start: int,
        range_end: int,
        include_branches: bool,
    ) -> Iterator[int]:
        """Yield addresses inside the range that may end a gadget."""
        raise NotImplementedError

    def is_terminator(self, instruction: DecodedInstruction, include_branches: bool) -> bool:
        """Whether a decoded candidate really ends a gadget."""
        raise NotImplementedError

    def is_branch(self, instruction: DecodedInstruction) -> bool:
        """Whether an instruction is a jump that needs the jump-gadget setting."""
        raise NotImplementedError

    def is_leave(self, instruction: DecodedInstruction) -> bool:
        """Whether an instruction is this architecture's frame teardown."""
        raise NotImplementedError

    def skips_interior(
        self,
        instruction: DecodedInstruction,
        include_branches: bool,
        include_leave: bool,
    ) -> bool:
        """Whether an instruction invalidates a gadget when it precedes the terminator."""
        if instruction.mnemonic in self.return_mnemonics:
            return True
        if not include_branches and self.is_branch(instruction):
            return True
        return not include_leave and self.is_leave(instruction)

    def gadget_starts(self, start_addr: int, end_addr: int) -> range:
        """Candidate gadget starts between two inclusive addresses, honoring alignment."""
        alignment = self.alignment
        first = start_addr + (-start_addr % alignment)
        return range(first, end_addr + 1, alignment)

    def matches_category(self, gadget_text: str, category: str) -> bool:
        """Whether lowercase gadget text belongs to a sidebar category."""
        pattern = self.category_patterns.get(category)
        return pattern is None or pattern.search(gadget_text) is not None


# x86 / x86-64: byte-granular backtracking from exact ret bytecodes.
#
# retn (c3) and retf (cb) are single-byte instructions, so every occurrence of
# those bytes is a usable gadget terminator regardless of instruction alignment.
_X86_RET_BYTECODES = (b"\xc3", b"\xf2\xc3", b"\xcb")
_X86_RET_MNEMONICS = frozenset({"ret", "retn", "retf"})
_X86_CATEGORY_PATTERNS = {
    "pop": re.compile(r"\bpop\b"),
    "mov": re.compile(r"\bmov\b"),
    "call": re.compile(r"\bcall\b"),
    "stack": re.compile(r"\b(leave|pop\s+rsp|xchg\s+rsp|mov\s+rsp|add\s+rsp|sub\s+rsp)\b"),
    "branch": re.compile(r"\bj[a-z]*\b"),
    "leave": re.compile(r"\bleave\b"),
}


class X86Profile(ArchProfile):
    alignment = 1
    return_mnemonics = _X86_RET_MNEMONICS
    category_patterns = _X86_CATEGORY_PATTERNS

    def terminator_candidates(
        self,
        bv: BinaryView,
        range_start: int,
        range_end: int,
        include_branches: bool,
    ) -> Iterator[int]:
        for bytecode in _X86_RET_BYTECODES:
            next_start = range_start
            while next_start < range_end:
                address = bv.find_next_data(next_start, bytecode)
                if address is None or address >= range_end:
                    break
                if address + len(bytecode) <= range_end:
                    yield address
                next_start = address + 1

    def is_terminator(self, instruction: DecodedInstruction, include_branches: bool) -> bool:
        # Candidates come from exact ret bytecodes and x86 has no instruction alignment,
        # so whatever decodes at a candidate address is already a return.
        return True

    def is_branch(self, instruction: DecodedInstruction) -> bool:
        return instruction.mnemonic.startswith("j")

    def is_leave(self, instruction: DecodedInstruction) -> bool:
        return instruction.mnemonic == "leave"


# AArch64: 4-byte aligned instructions, so gadgets can only start on aligned words.
#
# Every instruction of the RET encoding group has the bytes 5F D6 in its upper half
# word; the BR and BLR groups (indirect branches) do the same with 1F D6 and 3F D6.
# Scanning for those byte pairs finds every candidate terminator with one pass per
# pattern, and the decoder then decides whether the candidate is really a terminator.
_AARCH64_RET_SUFFIXES = (b"\x5f\xd6",)
_AARCH64_BRANCH_SUFFIXES = (b"\x1f\xd6", b"\x3f\xd6")
_AARCH64_RET_MNEMONICS = frozenset({"ret", "retaa", "retab"})
_AARCH64_BRANCH_TERMINATORS = frozenset({"br", "blr", "braa", "brab", "blraa", "blrab"})
_AARCH64_JUMP_MNEMONICS = frozenset({"b", "br", "braa", "brab", "cbz", "cbnz", "tbz", "tbnz"})
_AARCH64_LEAVE = re.compile(r"\b(?:mov|add)\s+sp,\s*x29\b")
_AARCH64_CATEGORY_PATTERNS = {
    "pop": re.compile(r"\b(?:pop|ldp|ldur|ldr[a-z]*)\b[^;]*\bsp\b"),
    "mov": re.compile(r"\bmov[a-z]*\b"),
    "call": re.compile(r"\b(?:bl|blr|blraa|blrab)\b"),
    "stack": re.compile(r"\b(?:mov|add|sub)\s+sp,"),
    "branch": re.compile(r"\b(?:b|br|braa|brab|cbz|cbnz|tbz|tbnz)(?:\.[a-z]+)?\b"),
    "leave": _AARCH64_LEAVE,
}


class AArch64Profile(ArchProfile):
    alignment = 4
    return_mnemonics = _AARCH64_RET_MNEMONICS
    category_patterns = _AARCH64_CATEGORY_PATTERNS

    def terminator_candidates(
        self,
        bv: BinaryView,
        range_start: int,
        range_end: int,
        include_branches: bool,
    ) -> Iterator[int]:
        suffixes = _AARCH64_RET_SUFFIXES
        if include_branches:
            suffixes += _AARCH64_BRANCH_SUFFIXES

        for suffix in suffixes:
            next_start = range_start
            while next_start < range_end:
                pattern_addr = bv.find_next_data(next_start, suffix)
                if pattern_addr is None or pattern_addr >= range_end:
                    break
                next_start = pattern_addr + 1

                # The byte pair is the top half of the word, so the instruction
                # starts two bytes earlier and only aligned words hold instructions.
                address = pattern_addr - 2
                if pattern_addr % self.alignment != 2:
                    continue
                if address < range_start or address + self.alignment > range_end:
                    continue
                yield address

    def is_terminator(self, instruction: DecodedInstruction, include_branches: bool) -> bool:
        if instruction.mnemonic in _AARCH64_RET_MNEMONICS:
            return True
        return include_branches and instruction.mnemonic in _AARCH64_BRANCH_TERMINATORS

    def is_branch(self, instruction: DecodedInstruction) -> bool:
        # Conditional branches decode as b.eq, b.ne, and friends on AArch64.
        mnemonic = instruction.mnemonic.split(".", 1)[0]
        return mnemonic in _AARCH64_JUMP_MNEMONICS

    def is_leave(self, instruction: DecodedInstruction) -> bool:
        # The AArch64 frame teardown is `mov sp, x29` (the `leave` of this ISA).
        return _AARCH64_LEAVE.search(instruction.text) is not None


_AARCH64_ARCH_NAMES = frozenset({"aarch64", "aarch64_be", "arm64"})
_X86_PROFILE = X86Profile()
_AARCH64_PROFILE = AArch64Profile()


def arch_profile_for_view(bv: BinaryView | None) -> ArchProfile:
    """
    Gadget rules for a view's architecture.

    Unknown architectures fall back to the x86 rules, which is ROPNinja's
    historical scanning behavior for every view.
    """
    arch = getattr(bv, "arch", None)
    name = (getattr(arch, "name", "") or "").lower()
    if name in _AARCH64_ARCH_NAMES:
        return _AARCH64_PROFILE
    return _X86_PROFILE
