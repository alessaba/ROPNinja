"""
Test support: a stand-in for the BinaryView surface that ROPNinja uses.

The plugin only needs segments, sections, raw reads, ``find_next_data``, and
instruction decoding from a view. These fakes model that surface over a flat byte
image and decode with capstone, so the gadget finder runs without Binary Ninja.
"""

import re

import capstone
from bnstub import TokenType

from ropninja import find_rop_gadgets_in_view, register_plugin_settings

register_plugin_settings()

_OPERAND_TYPES = (
    (re.compile(r"^#|^-?0x[0-9a-f]+$|^[0-9]+$"), TokenType.IntegerToken),
    (re.compile(r"^(sp|lr|xzr|wzr)$|^[xw][0-9]+$|^[re][a-z]{2}$|^r[0-9]+[dwb]?$"), TokenType.RegisterToken),
)


class FakeToken:
    __slots__ = ("text", "type")

    def __init__(self, token_type, text):
        self.type = token_type
        self.text = text


class FakeRange:
    """Anything with start/end, used for segments and sections."""

    def __init__(self, start, end, executable=True, semantics=None):
        self.start = start
        self.end = end
        self.executable = executable
        self.semantics = semantics


_AARCH64 = ("aarch64", capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN, 4)
_X86_64 = ("x86_64", capstone.CS_ARCH_X86, capstone.CS_MODE_64, 15)


class FakeArchitecture:
    """Decodes instructions with capstone and emits Binary Ninja style tokens."""

    def __init__(self, name="aarch64"):
        self.name, cs_arch, cs_mode, self.max_instr_length = (
            _AARCH64 if name.startswith("aarch64") else _X86_64
        )
        self.disassembler = capstone.Cs(cs_arch, cs_mode)

    def get_instruction_text(self, data, addr):
        if not data:
            return (None, 0)

        decoded = list(self.disassembler.disasm(bytes(data), addr, count=1))
        if not decoded:
            return (None, 0)

        instruction = decoded[0]
        return (self.tokens_for(instruction), instruction.size)

    @staticmethod
    def tokens_for(instruction):
        tokens = [FakeToken(TokenType.InstructionToken, instruction.mnemonic)]
        if not instruction.op_str:
            return tokens

        tokens.append(FakeToken(TokenType.TextToken, " "))
        for index, operand in enumerate(instruction.op_str.split(", ")):
            if index:
                tokens.append(FakeToken(TokenType.OperandSeparatorToken, ", "))
            token_type = TokenType.TextToken
            for pattern, candidate_type in _OPERAND_TYPES:
                if pattern.match(operand):
                    token_type = candidate_type
                    break
            tokens.append(FakeToken(token_type, operand))
        return tokens


class FakeView:
    """A flat image presented as a BinaryView, with one segment over it by default."""

    #: Empty by default; tests drive the finder through segments or sections.
    functions: tuple = ()
    instructions: tuple = ()

    def __init__(
        self,
        image,
        base=0x1000,
        arch_name="aarch64",
        segments=None,
        sections=None,
    ):
        self.image = bytes(image)
        self.start = base
        self.arch = FakeArchitecture(arch_name)
        self.executable = True
        self.segments = [FakeRange(base, base + len(self.image))] if segments is None else segments
        self.sections = sections if sections is not None else {}

    def read(self, addr, length):
        offset = addr - self.start
        if offset < 0 or offset >= len(self.image):
            return None
        return self.image[offset : offset + length]

    def find_next_data(self, start, data):
        index = self.image.find(data, max(start - self.start, 0))
        return None if index < 0 else self.start + index


def image(*parts) -> bytes:
    """
    Build an image from hex strings (byte order as stored in memory) or raw bytes.

    Example: ``image("c0035fd6", b"\\x1f\\x20\\x03\\xd5")`` is ``ret`` then ``nop``.
    """
    result = bytearray()
    for part in parts:
        result += bytes.fromhex(part) if isinstance(part, str) else bytes(part)
    return bytes(result)


def words(*encodings: str) -> bytes:
    """Build an image from 4-byte AArch64 instruction words given as hex strings."""
    result = bytearray()
    for encoding in encodings:
        result += bytes.fromhex(encoding)
    return bytes(result)


def gadgets_for(view, **kwargs):
    """Absolute gadget address -> gadget text for a view."""
    return {
        view.start + rva: gadget.text
        for rva, gadget in find_rop_gadgets_in_view(view, **kwargs).items()
    }
