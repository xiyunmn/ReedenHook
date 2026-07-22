#!/usr/bin/env python3
"""Find Dart AOT object-pool loads for selected Reeden pp.txt offsets."""

from __future__ import annotations

import argparse
import bisect
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from elftools.elf.elffile import ELFFile


FUNC_RE = re.compile(r"// \*\* addr: (0x[0-9a-fA-F]+), size:")


@dataclass(frozen=True)
class FunctionName:
    addr: int
    name: str
    file: str
    line: int


@dataclass(frozen=True)
class Segment:
    va: int
    file_offset: int
    size: int
    data: bytes


def parse_target(value: str) -> int:
    value = value.strip()
    if value.startswith("pp+"):
        value = value[3:]
    return int(value, 0)


def load_function_names(asm_dir: Path) -> list[FunctionName]:
    names: list[FunctionName] = []
    for path in asm_dir.rglob("*.dart"):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            match = FUNC_RE.search(line)
            if not match:
                continue
            header = lines[index - 1].strip() if index else "<unknown>"
            names.append(
                FunctionName(
                    int(match.group(1), 16),
                    header,
                    str(path),
                    index,
                )
            )
    names.sort(key=lambda item: item.addr)
    return names


def nearest_function(functions: list[FunctionName], addr: int) -> FunctionName | None:
    positions = [item.addr for item in functions]
    index = bisect.bisect_right(positions, addr) - 1
    if index < 0:
        return None
    return functions[index]


def executable_segments(so_path: Path) -> Iterable[Segment]:
    with so_path.open("rb") as f:
        elf = ELFFile(f)
        for segment in elf.iter_segments():
            header = segment.header
            if header.p_type != "PT_LOAD" or (header.p_flags & 1) == 0:
                continue
            data = segment.data()
            yield Segment(
                va=int(header.p_vaddr),
                file_offset=int(header.p_offset),
                size=len(data),
                data=data,
            )


def is_add_x_from_pp(insn: int) -> tuple[int, int] | None:
    # ADD (immediate), 64-bit, no flags. PP is x27 in Dart AOT.
    if (insn & 0x7F000000) != 0x11000000:
        return None
    if ((insn >> 31) & 1) != 1:
        return None
    rn = (insn >> 5) & 0x1F
    if rn != 27:
        return None
    rd = insn & 0x1F
    imm12 = (insn >> 10) & 0xFFF
    shift = (insn >> 22) & 0x3
    if shift == 0:
        base = imm12
    elif shift == 1:
        base = imm12 << 12
    else:
        return None
    return rd, base


def ldr_x_unsigned(insn: int) -> tuple[int, int, int] | None:
    # LDR (immediate, unsigned), 64-bit: Rt, [Rn, #imm12*8].
    if ((insn >> 22) & 0x3FF) != 0x3E5:
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    byte_offset = ((insn >> 10) & 0xFFF) * 8
    return rt, rn, byte_offset


def scan_pp_refs(
    so_path: Path,
    targets: set[int],
    functions: list[FunctionName],
) -> None:
    for segment in executable_segments(so_path):
        words = [
            struct.unpack_from("<I", segment.data, offset)[0]
            for offset in range(0, len(segment.data) - 3, 4)
        ]
        for index, insn in enumerate(words[:-1]):
            direct = ldr_x_unsigned(insn)
            if direct and direct[1] == 27:
                pp_offset = direct[2]
                if pp_offset in targets:
                    addr = segment.va + index * 4
                    fn = nearest_function(functions, addr)
                    print_hit(addr, pp_offset, fn, "ldr")

            add = is_add_x_from_pp(insn)
            if not add:
                continue
            reg, base = add
            for lookahead in range(1, min(5, len(words) - index)):
                load = ldr_x_unsigned(words[index + lookahead])
                if not load or load[1] != reg:
                    continue
                pp_offset = base + load[2]
                if pp_offset in targets:
                    addr = segment.va + index * 4
                    fn = nearest_function(functions, addr)
                    print_hit(addr, pp_offset, fn, f"add+ldr(+{lookahead})")


def print_hit(addr: int, pp_offset: int, fn: FunctionName | None, kind: str) -> None:
    owner = "<unknown>"
    location = ""
    if fn is not None:
        owner = fn.name
        location = f" {fn.file}:{fn.line + 1}"
    print(f"0x{addr:08x} pp+0x{pp_offset:05x} {kind} :: {owner}{location}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--so",
        default="apktool_out/Reeden_1.36.1/lib/arm64-v8a/libapp.so",
    )
    parser.add_argument("--asm-dir", default="blutter_out/Reeden_1.36.1/asm")
    parser.add_argument(
        "offsets",
        nargs="*",
        default=[
            "0x61d28",
            "0x61d48",
            "0x64900",
            "0x64920",
            "0x64990",
            "0x652f0",
            "0x65330",
            "0x65338",
            "0x978f8",
        ],
        help="object-pool offsets, e.g. pp+0x64990",
    )
    args = parser.parse_args()

    targets = {parse_target(item) for item in args.offsets}
    functions = load_function_names(Path(args.asm_dir))
    scan_pp_refs(Path(args.so), targets, functions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
