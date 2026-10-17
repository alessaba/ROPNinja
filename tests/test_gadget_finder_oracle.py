"""
Differential test: the finder must agree with an independent brute-force enumeration.

The oracle walks every candidate gadget start in an image, decodes with the same
capstone-backed architecture stand-in, and applies its own copy of the architecture
rules. Agreement exercises the parts that are easy to get wrong: terminator
discovery, instruction alignment, backtracking bounds, and interior filtering.
"""

import random
import unittest

from support import FakeArchitecture, FakeView, find_rop_gadgets_in_view, image, words

BASE = 0x1000

# The oracle keeps its own copy of the architecture rules on purpose: it must not
# read them from the code under test, or the comparison would be circular.
AARCH64_RULES = {
    "alignment": 4,
    "returns": {"ret", "retaa", "retab"},
    "jumps": {"b", "br", "braa", "brab", "cbz", "cbnz", "tbz", "tbnz"},
    "branch_terminators": {"br", "blr", "braa", "brab", "blraa", "blrab"},
    "leave": "mov sp, x29",
}
X86_RULES = {
    "bytecodes": (b"\xc3", b"\xf2\xc3", b"\xcb"),
    "alignment": 1,
    "returns": {"ret", "bnd ret", "retf", "rep ret"},
    "jumps": "j",
    "branch_terminators": set(),
    "leave": "leave",
}


class Decoder:
    """Instruction decoding shared by the oracle, mirroring the plugin's text rules."""

    def __init__(self, image_bytes, arch_name):
        self.image = image_bytes
        self.arch = FakeArchitecture(arch_name)
        self.cache = {}

    def decode(self, address):
        if address not in self.cache:
            data = self.image[address - BASE : address - BASE + self.arch.max_instr_length]
            tokens, length = self.arch.get_instruction_text(data, address)
            if tokens is None or length <= 0:
                self.cache[address] = None
            else:
                text = " ".join("".join(token.text for token in tokens).split())
                self.cache[address] = (text, text.split(maxsplit=1)[0].lower().rstrip(":"), length)
        return self.cache[address]


def terminator_candidates(image_bytes, rules, include_branches):
    """Every address in the image whose encoding may end a gadget."""
    candidates = set()
    if "bytecodes" in rules:
        for bytecode in rules["bytecodes"]:
            start = 0
            while True:
                index = image_bytes.find(bytecode, start)
                if index < 0:
                    break
                if index + len(bytecode) <= len(image_bytes):
                    candidates.add(BASE + index)
                start = index + 1
        return candidates

    suffixes = [b"\x5f\xd6"]
    if include_branches:
        suffixes += [b"\x1f\xd6", b"\x3f\xd6"]
    for index in range(0, len(image_bytes) - 3, 4):
        if image_bytes[index + 2 : index + 4] in suffixes:
            candidates.add(BASE + index)
    return candidates


def oracle_gadgets(image_bytes, arch_name, max_previous_bytes, include_branches, include_leave):
    rules = AARCH64_RULES if arch_name == "aarch64" else X86_RULES
    alignment = rules["alignment"]
    decoder = Decoder(image_bytes, arch_name)

    def rejected(text, mnemonic):
        branch_base = mnemonic.split(".", 1)[0]  # b.eq, b.ne, and friends
        jumps = rules["jumps"]
        is_jump = branch_base.startswith(jumps) if isinstance(jumps, str) else branch_base in jumps
        leave = rules["leave"]
        is_leave = leave in text if isinstance(leave, str) else leave.search(text)
        return (
            mnemonic in rules["returns"]
            or (not include_branches and is_jump)
            or (not include_leave and is_leave)
        )

    gadgets = {}
    for terminator in sorted(terminator_candidates(image_bytes, rules, include_branches)):
        decoded_terminator = decoder.decode(terminator)
        if decoded_terminator is None:
            continue
        _, mnemonic, _ = decoded_terminator
        is_branch_terminator = include_branches and mnemonic in rules["branch_terminators"]
        if mnemonic not in rules["returns"] and not is_branch_terminator:
            continue

        first_start = max(BASE, terminator - max_previous_bytes)
        first_start += -first_start % alignment
        for gadget_start in range(first_start, terminator + 1, alignment):
            address = gadget_start
            instructions = []
            while address < terminator:
                decoded = decoder.decode(address)
                if decoded is None:
                    break
                text, mnemonic, length = decoded
                if rejected(text, mnemonic):
                    break
                instructions.append(text)
                address += length

            if address == terminator and (instructions or gadget_start == terminator):
                gadgets[gadget_start] = " ; ".join([*instructions, decoded_terminator[0]])
    return gadgets


AARCH64_WORD_POOL = [
    "c0035fd6",  # ret
    "00015fd6",  # ret x8
    "ff0b5fd6",  # retaa
    "ff0f5fd6",  # retab
    "fd7bc1a8",  # ldp x29, x30, [sp], #16
    "bf030091",  # mov sp, x29
    "ff430091",  # add sp, sp, #16
    "e00740f9",  # ldr x0, [sp, #8]
    "10000094",  # bl #0x40
    "00020054",  # b.eq #0x40
    "000200b4",  # cbz x0, #0x40
    "00021fd6",  # br x16
    "00013fd6",  # blr x8
    "1f2003d5",  # nop
    "080440f9",  # ldr x8, [x0, #8]
    "e00301aa",  # mov x0, x1
    "e0039fd6",  # eret
    "5fd61234",  # 5F D6 in the low half of a word
    "005fd600",  # 5F D6 in the middle of a word
    "fff05fd6",  # ret group encoding that does not decode
]
X86_BYTE_POOL = [b"\x5f", b"\xc3", b"\xcb", b"\xc9", b"\xeb\x05", b"\x90", b"\x0f\x05"]


def stress_image(arch_name, words_count, random_source):
    if arch_name == "aarch64":
        pool = [bytes.fromhex(word) for word in AARCH64_WORD_POOL]
        return b"".join(
            random_source.choice(pool) if random_source.random() < 0.35 else random_source.randbytes(4)
            for _ in range(words_count)
        )

    parts = [
        random_source.choice(X86_BYTE_POOL) if random_source.random() < 0.25 else random_source.randbytes(1)
        for _ in range(words_count)
    ]
    return b"".join(parts)


class OracleAgreementTest(unittest.TestCase):
    def assert_agrees(self, image_bytes, arch_name, **kwargs):
        view = FakeView(image_bytes, arch_name=arch_name)
        found = find_rop_gadgets_in_view(view, **kwargs)
        found_by_address = {BASE + rva: gadget.text for rva, gadget in found.items()}
        expected = oracle_gadgets(
            image_bytes,
            arch_name,
            kwargs.get("max_previous_bytes", 32),
            kwargs.get("include_branches", False),
            kwargs.get("include_leave", False),
        )
        self.assertEqual(found_by_address, expected)
        return expected

    def test_aarch64_instruction_stream(self):
        golden = words(
            "c0035fd6", "00015fd6", "ff0b5fd6", "ff0f5fd6", "fd7bc1a8", "f35342a9",
            "bf030091", "ff430091", "ff8300d1", "e00740f9", "e20f4039", "10000094",
            "00020054", "000200b4", "01021836", "00021fd6", "00013fd6", "10000014",
            "1f2003d5", "e00301aa", "410c0091", "fd7bbfa9", "080440f9", "088440f8",
            "000080d2", "00423bd5", "e0039fd6", "c0035fd6",
        )
        for options in (
            {},
            {"include_branches": True},
            {"include_leave": True},
            {"include_branches": True, "include_leave": True},
            {"max_previous_bytes": 8},
            {"max_previous_bytes": 128, "include_branches": True, "include_leave": True},
        ):
            with self.subTest(options=options):
                found = self.assert_agrees(golden, "aarch64", **options)
                self.assertTrue(found)

    def test_aarch64_random_words(self):
        random_source = random.Random(0xA64)
        stress = stress_image("aarch64", 1024, random_source)
        for options in (
            {},
            {"include_branches": True},
            {"include_leave": True},
            {"include_branches": True, "include_leave": True, "max_previous_bytes": 64},
        ):
            with self.subTest(options=options):
                found = self.assert_agrees(stress, "aarch64", **options)
                self.assertTrue(any(" ; " in text for text in found.values()))

    def test_x86_random_bytes(self):
        random_source = random.Random(0x86)
        stress = stress_image("x86_64", 2048, random_source)
        for options in (
            {},
            {"include_branches": True},
            {"include_leave": True},
            {"include_branches": True, "include_leave": True, "max_previous_bytes": 16},
        ):
            with self.subTest(options=options):
                found = self.assert_agrees(stress, "x86_64", **options)
                self.assertTrue(any(" ; " in text for text in found.values()))

    def test_x86_noise_bytecodes_are_terminators(self):
        stream = image("90", "f2c3", "90", "cb", "90", "c3")
        for options in ({}, {"include_branches": True}, {"max_previous_bytes": 6}):
            with self.subTest(options=options):
                found = self.assert_agrees(stream, "x86_64", **options)
                self.assertIn(0x1001, found)


if __name__ == "__main__":
    unittest.main()
