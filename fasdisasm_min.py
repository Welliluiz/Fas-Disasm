#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import sys
from pathlib import Path


PROTECTED_LISP_SIGNATURE = b"AutoCAD PROTECTED LISP file"
VLX_SIGNATURE = b"VRTLIB-1"
FAS_SIGNATURES = (
    b"FAS4-FILE",
    b"FAS3-FILE",
    b"FAS2-FILE",
    b"FAS-FILE",
    b"1Y",
)

BYTE_1A_EOF = 0x1A
BYTE_0D_CR = 0x0D
BYTE_0A_LF = 0x0A

VLX_TYPE_EXTENSIONS = {
    0x0000: "lsp",
    0x04D8: "prv",
    0x0537: "txt",
    0x0532: "fas",
    0x0546: "dcl",
    0x053C: "dvb",
}


class FasDisasmMinError(RuntimeError):
    pass


class ByteReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def tell(self) -> int:
        return self.pos

    def read(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise FasDisasmMinError("unexpected end of file")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def read_byte(self) -> int:
        return self.read(1)[0]

    def read_char(self) -> str:
        return chr(self.read_byte())

    def read_until(self, terminator: bytes) -> bytes:
        start = self.pos
        index = self.data.find(terminator, self.pos)
        if index == -1:
            raise FasDisasmMinError("terminator not found")
        self.pos = index + len(terminator)
        return self.data[start:index]


def is_ws_or_ctrl(value: int) -> bool:
    return value <= 0x20 or value == 0x1A


def skip_whitespace(reader: ByteReader) -> str:
    while True:
        char = reader.read_char()
        if not is_ws_or_ctrl(ord(char)):
            return char


def skip_whitespace_ex(reader: ByteReader) -> str:
    char = skip_whitespace(reader)
    while char == ";":
        while True:
            char = reader.read_char()
            if char in ("\r", "\n"):
                break
        char = skip_whitespace(reader)
    return char


def read_number(reader: ByteReader, first_char: str | None = None) -> int:
    char = first_char if first_char is not None else skip_whitespace_ex(reader)
    if not char.isdigit():
        raise FasDisasmMinError(f"expected numeric field, got {char!r}")

    digits = [char]
    while not reader.eof():
        char = reader.read_char()
        if not char.isdigit():
            break
        digits.append(char)
    return int("".join(digits))


def decrypt_fas_stream(stream_data: bytes, key: bytes) -> bytes:
    if not key:
        return stream_data

    output = bytearray()
    key_old = key[0]
    key_index = 0
    for byte in stream_data:
        key_index = (key_index + 1) % len(key)
        key_new = key[key_index]
        output.append(byte ^ key_new ^ key_old)
        key_old = key_new
    return bytes(output)


def extract_stream(reader: ByteReader, data_length: int) -> tuple[bytes, int, int]:
    stream_vars = read_number(reader)
    tmp_char = skip_whitespace(reader)
    if tmp_char == "!":
        stream_terminator = reader.read_char()
    else:
        stream_terminator = tmp_char

    code_start = reader.tell()
    stream_data = reader.read(data_length)

    if reader.eof():
        return stream_data, stream_vars, code_start

    tmp_char = reader.read_char()
    is_encrypted = tmp_char != stream_terminator
    if not is_encrypted:
        return stream_data, stream_vars, code_start

    key_length = ord(tmp_char)
    if key_length >= 0x80:
        raise FasDisasmMinError("crunch password too long")
    key = reader.read(key_length)
    end_marker = reader.read_char()
    if end_marker != stream_terminator:
        raise FasDisasmMinError("stream terminator mismatch after encryption key")

    return decrypt_fas_stream(stream_data, key), stream_vars, code_start


def extract_fas_like(input_path: Path, output_dir: Path | None = None) -> dict[str, object]:
    data = input_path.read_bytes()
    reader = ByteReader(data)
    first_char = skip_whitespace_ex(reader)

    is_fsl = first_char == "#"
    if output_dir is None:
        output_dir = input_path.with_name(f"{input_path.name}_out")
    output_dir.mkdir(parents=True, exist_ok=True)

    if is_fsl:
        signature = reader.read_until(b"#").decode("latin-1")
        if signature != "1Y":
            raise FasDisasmMinError(f"invalid FSL signature: {signature!r}")
        version = "fsl"

        function_length = int(reader.read_until(b"m").decode("latin-1"))
        function_stream, function_vars, function_offset = extract_stream(reader, function_length)

        reader.read_until(b"#")
        resource_length = int(reader.read_until(b"m").decode("latin-1"))
        resource_stream, resource_vars, resource_offset = extract_stream(reader, resource_length)
    else:
        signature_chars = [first_char]
        while reader.tell() < min(len(data), 1024):
            char = reader.read_char()
            if not (char.isalnum() or char == "-"):
                break
            signature_chars.append(char)
        signature = "".join(signature_chars)
        if signature not in ("FAS4-FILE", "FAS3-FILE", "FAS2-FILE", "FAS-FILE"):
            raise FasDisasmMinError(f"invalid FAS signature: {signature!r}")
        version = signature

        function_length = read_number(reader)
        function_stream, function_vars, function_offset = extract_stream(reader, function_length)

        resource_length = read_number(reader)
        resource_stream, resource_vars, resource_offset = extract_stream(reader, resource_length)

    fct_path = output_dir / f"{input_path.name}.fct"
    res_path = output_dir / f"{input_path.name}.res"
    metadata_path = output_dir / f"{input_path.name}.metadata.json"
    dump_path = output_dir / f"{input_path.name}.txt"
    semantic_path = output_dir / f"{input_path.name}.sem.txt"
    pseudo_path = output_dir / f"{input_path.name}.pseudo.lsp"
    lsp_path = output_dir / f"{input_path.name}.lsp"

    fct_path.write_bytes(function_stream)
    res_path.write_bytes(resource_stream)
    metadata = {
        "input": str(input_path),
        "kind": "fsl" if is_fsl else "fas",
        "version": version,
        "function_stream_length": len(function_stream),
        "function_stream_vars": function_vars,
        "function_offset": function_offset,
        "resource_stream_length": len(resource_stream),
        "resource_stream_vars": resource_vars,
        "resource_offset": resource_offset,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    dump_path.write_text(
        build_combined_stream_dump(function_stream, resource_stream, metadata),
        encoding="utf-8",
    )
    semantic_path.write_text(
        build_semantic_dump(function_stream, resource_stream, metadata),
        encoding="utf-8",
    )
    pseudo_path.write_text(
        build_pseudolisp_dump(function_stream, resource_stream, metadata),
        encoding="utf-8",
    )
    lsp_path.write_text(
        build_final_lisp_dump(function_stream, resource_stream, metadata),
        encoding="utf-8",
    )
    return {
        "fct_path": fct_path,
        "res_path": res_path,
        "metadata_path": metadata_path,
        "dump_path": dump_path,
        "semantic_path": semantic_path,
        "pseudo_path": pseudo_path,
        "lsp_path": lsp_path,
        "metadata": metadata,
    }


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end == -1:
        raise FasDisasmMinError("unterminated zero string")
    return data[offset:end].decode("latin-1", errors="replace"), end + 1


def decode_stream_instruction(data: bytes, offset: int) -> tuple[int, str]:
    op = data[offset]
    pos = offset + 1

    def need(size: int) -> None:
        if pos + size > len(data):
            raise FasDisasmMinError(f"truncated opcode 0x{op:02X} at 0x{offset:04X}")

    def u8() -> int:
        nonlocal pos
        need(1)
        value = data[pos]
        pos += 1
        return value

    def s8() -> int:
        value = u8()
        return value - 256 if value >= 0x80 else value

    def u16() -> int:
        nonlocal pos
        need(2)
        value = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        return value

    def s16() -> int:
        nonlocal pos
        need(2)
        value = struct.unpack_from("<h", data, pos)[0]
        pos += 2
        return value

    def s32() -> int:
        nonlocal pos
        need(4)
        value = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        return value

    if op in (0x14, 0x15):
        local_low = u8()
        args_min = u8()
        args_max = u8()
        flags = u8()
        local_vars = ((flags & 0xFE) * 0x80) | local_low
        return pos, (
            f"DEFUN args={args_min}..{args_max} locals={local_vars} "
            f"cleanup={flags & 0x1}"
        )
    if op == 0x16:
        return pos, "END_DEFUN"
    if op == 0x17:
        return pos, "MAIN_FAS2"
    if op == 0x1C:
        return pos, "INIT_DONE"
    if op == 0x20:
        return pos, "NOP_SPACE"
    if op == 0x00:
        return pos, "PAD_00"
    if op == 0x01:
        return pos, "PUSH_NIL"
    if op == 0x02:
        return pos, "PUSH_T"
    if op == 0x03:
        value = u16()
        return pos, f"PUSH_GVAR_VALUE #{value}"
    if op == 0x04:
        idx = u8()
        stream_id = u8()
        return pos, f"PUSH_STREAM_REF idx={idx} stream={stream_id}"
    if op in (0x05, 0x08, 0x64):
        value = u8()
        return pos, f"LOCAL8 idx={value}"
    if op == 0x06:
        value = u16()
        return pos, f"SETQ #{value}"
    if op in (0x09, 0x0C):
        value = u16()
        return pos, f"PUSH_GVAR_ITEM #{value}"
    if op == 0x0A:
        return pos, "POP"
    if op == 0x0B:
        return pos, "DUP"
    if op in (0x0D, 0x0E, 0x0F, 0x3C, 0x3D):
        delta = s16()
        return pos, f"BR16 delta={delta:+d} target=0x{pos + delta:04X}"
    if op == 0x10:
        value1 = u8()
        value2 = u8()
        return pos, f"LIST_STEP {value1} {value2}"
    if op in (0x18, 0x19, 0x1A, 0x1B, 0x21):
        value = u16()
        return pos, f"U16 {value}"
    if op in (0x1E, 0x1F, 0x25, 0x2C, 0x2D):
        value = u8()
        return pos, f"U8 {value}"
    if op in (0x23, 0x24, 0x26, 0x28, 0x29, 0x2A):
        return pos, {
            0x23: "NULL_OR_NOT",
            0x24: "ATOM",
            0x26: "SUB",
            0x28: "CAR",
            0x29: "CDR",
            0x2A: "CONS",
        }[op]
    if op == 0x32:
        value = s8()
        return pos, f"LD_INT8 {value}"
    if op == 0x33:
        value = s32()
        return pos, f"LD_INT32 {value}"
    if op == 0x39:
        value = u16()
        return pos, f"LD_LIST count={value}"
    if op == 0x3B:
        text, pos = read_cstring(data, pos)
        return pos, f"LD_REAL {text!r}"
    if op == 0x3A:
        return pos, "DEF_FUNC_FROM_STACK"
    if op == 0x43:
        var_pos = u16()
        init_count = u16()
        return pos, f"IVARS var_pos={var_pos} init_count={init_count}"
    if 0x46 <= op <= 0x4E:
        names = {
            0x46: "ADD",
            0x47: "SUB",
            0x48: "MUL",
            0x49: "DIV",
            0x4A: "MOD",
            0x4B: "LE",
            0x4C: "GE",
            0x4D: "LT",
            0x4E: "GT",
        }
        return pos, names[op]
    if op in (0x4F, 0x50):
        return pos, "INC" if op == 0x4F else "DEC"
    if op in (0x34, 0x35, 0x51):
        argc = u8()
        details = [f"argc={argc}"]
        if op in (0x35, 0x51):
            details.append(f"gvar={u16()}")
        details.append(f"flags=0x{u8():02X}")
        if op == 0x51:
            details.append(f"extra={u8()}")
        names = {0x34: "EVAL", 0x35: "LD_USUBR", 0x51: "FUNC"}
        return pos, f"{names[op]} {' '.join(details)}"
    if op == 0x55:
        count = u16()
        strings: list[str] = []
        for _ in range(count):
            size = u16()
            need(size)
            raw = data[pos : pos + size]
            pos += size
            strings.append(raw.decode("latin-1", errors="replace"))
        return pos, f"LD_STR count={count} values={strings!r}"
    if op in (0x56, 0x5B):
        values: list[str] = []
        while True:
            text, pos = read_cstring(data, pos)
            if not text:
                break
            values.append(text)
        return pos, f"LD_SYM count={len(values)} values={values!r}"
    if op == 0x57:
        delta = s32()
        return pos, f"GOTO delta={delta:+d} target=0x{pos + delta:04X}"
    if op == 0x59:
        return pos, "SETUP_ERROR_HANDLER"
    if op == 0x5A:
        argc = u8()
        target = s32()
        return pos, f"CALL_VL_ARX argc={argc} target={target}"
    if op in (0x5C, 0x5D, 0x5E):
        value = u16()
        return pos, f"LOCAL16 idx={value}"
    if op == 0x5F:
        argc = u8()
        target = s32()
        return pos, f"CALL_BY_OFFSET argc={argc} target=0x{target:04X}"
    if op == 0x60:
        argc = u8()
        target = s32()
        return pos, f"JMP2_NOPOP argc={argc} target=0x{target:04X}"
    if op == 0x61:
        argc = u8()
        target = s32()
        return pos, f"CONTINUE_AT argc={argc} target=0x{target:04X}"
    if op in (0x62, 0x63):
        return pos, f"NOP_{chr(op)}"
    if op in (0x67, 0x68, 0x69, 0x6A):
        delta = s32()
        return pos, f"BRANCH delta={delta:+d} target=0x{pos + delta:04X}"
    if op == 0x65:
        return pos, "TRACE_IN"
    if op == 0x66:
        return pos, "TRACE_OUT"
    if op in (0x11, 0x12, 0x13, 0x1D, 0x22, 0x27, 0x2B, 0x30, 0x31, 0x36, 0x41, 0x42, 0x44, 0x52, 0x58):
        return pos, f"STOP_0x{op:02X}"

    return pos, f"OP_0x{op:02X}"


def dump_stream(data: bytes, label: str) -> str:
    lines = [f"[{label}]"]
    offset = 0
    while offset < len(data):
        try:
            next_offset, text = decode_stream_instruction(data, offset)
        except FasDisasmMinError as exc:
            raw = data[offset : min(len(data), offset + 64)].hex(" ")
            lines.append(f"{offset:05d}  {raw:<28} DECODE_ERROR {exc}")
            lines.append(f"{offset:05d}  {data[offset:].hex(' ')}")
            break

        raw = data[offset:next_offset].hex(" ")
        lines.append(f"{offset:05d}  {raw:<28} {text}")
        if next_offset <= offset:
            lines.append(f"{offset:05d}  {data[offset:].hex(' ')}")
            break
        offset = next_offset
    return "\n".join(lines)


def build_combined_stream_dump(
    function_stream: bytes, resource_stream: bytes, metadata: dict[str, object]
) -> str:
    header = [
        f"kind: {metadata['kind']}",
        f"version: {metadata['version']}",
        f"function_stream_vars: {metadata['function_stream_vars']}",
        f"resource_stream_vars: {metadata['resource_stream_vars']}",
        "",
    ]
    body = [
        dump_stream(function_stream, "function_stream"),
        "",
        dump_stream(resource_stream, "resource_stream"),
    ]
    return "\n".join(header + body) + "\n"


def parse_semantic_instruction(data: bytes, offset: int) -> tuple[int, str, dict[str, object]]:
    op = data[offset]
    pos = offset + 1

    def need(size: int) -> None:
        if pos + size > len(data):
            raise FasDisasmMinError(f"truncated opcode 0x{op:02X} at 0x{offset:04X}")

    def u8() -> int:
        nonlocal pos
        need(1)
        value = data[pos]
        pos += 1
        return value

    def s8() -> int:
        value = u8()
        return value - 256 if value >= 0x80 else value

    def u16() -> int:
        nonlocal pos
        need(2)
        value = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        return value

    def s32() -> int:
        nonlocal pos
        need(4)
        value = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        return value

    def with_target(kind: str, delta: int) -> tuple[int, str, dict[str, object]]:
        return pos, kind, {"delta": delta, "target": pos + delta}

    if op in (0x14, 0x15):
        local_low = u8()
        args_min = u8()
        args_max = u8()
        flags = u8()
        return pos, "DEFUN", {
            "locals": ((flags & 0xFE) * 0x80) | local_low,
            "args_min": args_min,
            "args_max": args_max,
            "cleanup": flags & 1,
        }
    if op == 0x16:
        return pos, "END_DEFUN", {}
    if op == 0x01:
        return pos, "PUSH", {"value": "nil"}
    if op == 0x02:
        return pos, "PUSH", {"value": "T"}
    if op == 0x03:
        index = u16()
        return pos, "PUSH_GVAR_VALUE", {"index": index}
    if op == 0x04:
        index = u8()
        stream_id = u8()
        return pos, "PUSH_STREAM_REF", {"index": index, "stream_id": stream_id}
    if op in (0x05, 0x64):
        index = u8()
        return pos, "LOCAL8", {"index": index, "mode": "get"}
    if op == 0x08:
        index = u8()
        return pos, "LOCAL8", {"index": index, "mode": "set"}
    if op == 0x06:
        index = u16()
        return pos, "SETQ", {"index": index}
    if op == 0x09:
        index = u16()
        return pos, "PUSH_GVAR_ITEM", {"index": index}
    if op == 0x0C:
        index = u16()
        return pos, "PUSH_GVAR_ITEM", {"index": index}
    if op == 0x0A:
        return pos, "POP", {}
    if op == 0x0B:
        return pos, "DUP", {}
    if op in (0x0D, 0x0E, 0x0F, 0x3C, 0x3D):
        need(2)
        delta = struct.unpack_from("<h", data, pos)[0]
        pos += 2
        return with_target("BRANCH", delta)
    if op in (0x18, 0x19):
        value = u16()
        return pos, "U16", {"value": value}
    if op == 0x1C:
        return pos, "NOOP", {"text": "INIT_DONE"}
    if op in (0x00, 0x20):
        return pos, "NOOP", {"text": "PAD_00" if op == 0x00 else "NOP_SPACE"}
    if op == 0x23:
        return pos, "UNARY_CALL", {"name": "null-or-not"}
    if op == 0x24:
        return pos, "UNARY_CALL", {"name": "atom"}
    if op == 0x2A:
        return pos, "CONS", {}
    if op == 0x28:
        return pos, "UNARY_CALL", {"name": "car"}
    if op == 0x29:
        return pos, "UNARY_CALL", {"name": "cdr"}
    if op == 0x32:
        value = s8()
        return pos, "PUSH", {"value": value}
    if op == 0x33:
        value = s32()
        return pos, "PUSH", {"value": value}
    if op == 0x34:
        argc = u8()
        flags = u8()
        return pos, "EVAL", {"argc": argc, "flags": flags}
    if op == 0x35:
        argc = u8()
        gvar = u16()
        flags = u8()
        return pos, "CALL", {"argc": argc, "gvar": gvar, "flags": flags}
    if op == 0x39:
        count = u16()
        return pos, "LD_LIST", {"count": count}
    if op == 0x3B:
        text, pos = read_cstring(data, pos)
        return pos, "PUSH", {"value": text}
    if op == 0x3A:
        return pos, "DEF_FUNC_FROM_STACK", {}
    if op == 0x43:
        var_pos = u16()
        init_count = u16()
        return pos, "IVARS", {"var_pos": var_pos, "init_count": init_count}
    if op == 0x55:
        count = u16()
        values: list[str] = []
        for _ in range(count):
            size = u16()
            need(size)
            raw = data[pos : pos + size]
            pos += size
            values.append(raw.decode("latin-1", errors="replace"))
        return pos, "LD_STR", {"values": values}
    if op in (0x56, 0x5B):
        values: list[str] = []
        while True:
            text, pos = read_cstring(data, pos)
            if not text:
                break
            values.append(text)
        return pos, "LD_SYM", {"values": values}
    if op == 0x57:
        delta = s32()
        return with_target("GOTO", delta)
    if op == 0x59:
        return pos, "SETUP_ERROR_HANDLER", {}
    if op == 0x5A:
        argc = u8()
        target = s32()
        return pos, "CALL_VL_ARX", {"argc": argc, "target": target}
    if op in (0x5C, 0x5D):
        index = u16()
        return pos, "LOCAL16", {"index": index, "mode": "get" if op == 0x5C else "set"}
    if op == 0x5E:
        index = u16()
        return pos, "LOCAL16", {"index": index, "mode": "get"}
    if op == 0x5F:
        argc = u8()
        target = s32()
        return pos, "CALL_BY_OFFSET", {"argc": argc, "target": target}
    if op == 0x60:
        argc = u8()
        target = s32()
        return pos, "JMP2_NOPOP", {"argc": argc, "target": target}
    if op == 0x61:
        argc = u8()
        target = s32()
        return pos, "CONTINUE_AT", {"argc": argc, "target": target}
    if op in (0x62, 0x63, 0x65, 0x66):
        return pos, "NOOP", {"text": decode_stream_instruction(data, offset)[1]}
    if op == 0x67:
        delta = s32()
        return with_target("BRANCH", delta)
    if op == 0x68:
        delta = s32()
        return with_target("BRANCH", delta)
    if op == 0x69:
        delta = s32()
        return with_target("BRANCH", delta)
    if op == 0x6A:
        delta = s32()
        return with_target("BRANCH", delta)
    if 0x46 <= op <= 0x50:
        name = {
            0x46: "+",
            0x47: "-",
            0x48: "*",
            0x49: "/",
            0x4A: "mod",
            0x4B: "<=",
            0x4C: ">=",
            0x4D: "<",
            0x4E: ">",
            0x4F: "1+",
            0x50: "1-",
        }[op]
        return pos, "ARITH", {"name": name}
    if op == 0x51:
        argc = u8()
        gvar = u16()
        flags = u8()
        extra = u8()
        return pos, "FUNC", {"argc": argc, "gvar": gvar, "flags": flags, "extra": extra}

    next_pos, text = decode_stream_instruction(data, offset)
    return next_pos, "RAW", {"text": text}


def render_value(value: object) -> str:
    if isinstance(value, str):
        return value
    return str(value)


def format_target(offset: int) -> str:
    return f"0x{offset:04X}"


def safe_pop(stack: list[object]) -> tuple[object, bool]:
    if stack:
        return stack.pop(), False
    return "<stack-empty>", True


DEFUN_HEADER_RE = re.compile(r"^\(defun fn_([0-9A-F]+) \(&rest args\)(.*)$")
DEFUN_REF_RE = re.compile(r"^\s+\(defun-ref (.+?) :offset (\d+) :env .+\)$")
DEFUN_REF_INLINE_RE = re.compile(r"\(defun-ref ([^ )]+) :offset \d+ :env [^)]+\)")
GLOBAL_ASSIGNMENT_RE = re.compile(r"^\s*\(setq G\[(\d+)\] (.+)\)$")
FUNC_LINE_RE = re.compile(r"^(\s*)\(func (.+?) argc=(\d+) flags=0x([0-9A-F]+) extra=(\d+)\)$")
BRANCH_IF_RE = re.compile(r"^(\s*)\(branch-if (.+) (0x[0-9A-F]+)\)$")
GOTO_RE = re.compile(r"^(\s*)\(goto (0x[0-9A-F]+)\)$")
CALL_BY_OFFSET_RE = re.compile(r"\(call@0x([0-9A-F]+)\b")
COND_CLAUSE_RE = re.compile(r"^\s+\((.+) \(goto ([^)]+)\)\)$")
LABEL_RE = re.compile(r"^(\s*)\(label (:[A-Za-z0-9_]+)\)$")
BRANCH_LABEL_RE = re.compile(r"^(\s*\(branch-if .+ )(:[A-Za-z0-9_]+)(\))$")
GOTO_LABEL_RE = re.compile(r"\(goto (:[A-Za-z0-9_]+)\)")
PURE_GOTO_RE = re.compile(r"^\(goto (:[A-Za-z0-9_]+)\)$")


def is_symbolic_name(name: str) -> bool:
    return bool(name) and not any(char.isspace() for char in name) and not name.startswith(("(", '"'))


def format_call_expression(head: str, args: list[str]) -> str:
    return f"({head})" if not args else f"({head} {' '.join(args)})"


def is_discardable_popped_value(value: object) -> bool:
    if value in ("<stack-empty>", "nil"):
        return True
    if isinstance(value, (int, float)):
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if stripped.startswith("(defun-ref ") or stripped.startswith("(func "):
        return True
    return not stripped.startswith("(")


def collect_defun_names(lines: list[str]) -> dict[int, str]:
    names: dict[int, str] = {}
    for line in lines:
        match = DEFUN_REF_RE.match(line)
        if match:
            name = match.group(1)
            offset = int(match.group(2))
            if offset not in names and is_symbolic_name(name):
                names[offset] = name
        for inline_match in DEFUN_REF_INLINE_RE.finditer(line):
            name = inline_match.group(1)
            offset_match = re.search(r":offset (\d+)", inline_match.group(0))
            if not offset_match:
                continue
            offset = int(offset_match.group(1))
            if offset not in names and is_symbolic_name(name):
                names[offset] = name
    return names


def collect_stable_global_names(lines: list[str]) -> dict[int, str]:
    candidates: dict[int, str | None] = {}
    unstable: set[int] = set()

    for line in lines:
        match = GLOBAL_ASSIGNMENT_RE.match(line)
        if not match:
            continue

        index = int(match.group(1))
        rhs = match.group(2).strip()

        ref_match = DEFUN_REF_RE.fullmatch(rhs)
        if ref_match:
            value = ref_match.group(1)
        elif is_symbolic_name(rhs):
            value = rhs
        else:
            unstable.add(index)
            continue

        if index in unstable:
            continue

        current = candidates.get(index)
        if current is None:
            candidates[index] = value
        elif current != value:
            unstable.add(index)
            candidates.pop(index, None)

    return {index: value for index, value in candidates.items() if index not in unstable and value is not None}


def resolve_call_targets(line: str, defun_names: dict[int, str]) -> str:
    def replacer(match: re.Match[str]) -> str:
        offset = int(match.group(1), 16)
        name = defun_names.get(offset)
        if not name:
            return match.group(0)
        return f"({name}"

    return CALL_BY_OFFSET_RE.sub(replacer, line)


def simplify_defun_ref_text(text: str) -> str:
    ref_match = DEFUN_REF_RE.fullmatch(text.strip())
    if ref_match:
        return f"(function {ref_match.group(1)})"
    return text


def simplify_inline_defun_refs(text: str) -> str:
    return DEFUN_REF_INLINE_RE.sub(lambda match: f"(function {match.group(1)})", text)


def replace_stable_globals(text: str, global_names: dict[int, str]) -> str:
    if not global_names:
        return text

    def replacer(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return global_names.get(index, match.group(0))

    return re.sub(r"\bG\[(\d+)\]", replacer, text)


def simplify_final_lisp_line(line: str, defun_names: dict[int, str], global_names: dict[int, str]) -> str:
    stripped = line.strip()

    if stripped.startswith("; preds="):
        return ""

    if stripped.startswith("(block ") or stripped == ")" or stripped.startswith("(label "):
        return line

    line = resolve_call_targets(line, defun_names)
    line = simplify_inline_defun_refs(line)

    branch_match = re.match(r"^(\s*)\(branch-if (.+) (:[A-Za-z0-9_]+)\)$", line)
    if branch_match:
        indent, condition, target = branch_match.groups()
        if condition in ("nil", "(nil)"):
            return ""
        if condition in ("T", "t"):
            return f"{indent}(goto {target})"

    func_match = FUNC_LINE_RE.match(line)
    if func_match:
        indent, target, argc, flags, extra = func_match.groups()
        target = replace_stable_globals(simplify_defun_ref_text(target), global_names)
        return f"{indent}(function {target} :argc {argc} :flags 0x{flags} :extra {extra})"

    if stripped.startswith("(setq G["):
        match = GLOBAL_ASSIGNMENT_RE.match(line)
        if match:
            indent = line[: len(line) - len(line.lstrip())]
            index = int(match.group(1))
            rhs = match.group(2)
            rhs = simplify_defun_ref_text(rhs)
            rhs = simplify_inline_defun_refs(rhs)
            rhs = replace_stable_globals(rhs, global_names)
            return f"{indent}(setq G[{index}] {rhs})"
        return line

    line = simplify_defun_ref_text(line)
    line = simplify_inline_defun_refs(line)
    line = replace_stable_globals(line, global_names)
    line = line.replace("(call@", "(call ")
    return line


def form_span(lines: list[str], start: int) -> int:
    depth = 0
    in_string = False
    escape = False

    for index in range(start, len(lines)):
        for char in lines[index]:
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1

        if depth <= 0 and not in_string:
            return index

    return len(lines) - 1


def simplify_cond_block(block_lines: list[str]) -> list[str]:
    if len(block_lines) < 3 or block_lines[0].strip() != "(cond":
        return block_lines

    clauses: list[tuple[str, str]] = []
    for line in block_lines[1:-1]:
        stripped = line.strip()
        if not stripped:
            continue
        parsed = parse_cond_clause(line)
        if parsed is None:
            return block_lines
        clauses.append(parsed)

    if len(clauses) < 2:
        return block_lines

    for condition, target in clauses:
        if condition in ("T", "t"):
            indent = block_lines[0][: len(block_lines[0]) - len(block_lines[0].lstrip())]
            return [f"{indent}(goto {target})"]

    targets = {target for _, target in clauses}
    if len(targets) != 1:
        return block_lines

    target = next(iter(targets))
    indent = block_lines[0][: len(block_lines[0]) - len(block_lines[0].lstrip())]
    return [f"{indent}(goto {target})"]


def simplify_if_block(block_lines: list[str]) -> list[str]:
    if len(block_lines) < 4:
        return block_lines

    header = block_lines[0].strip()
    match = re.match(r"^\(if (.+)$", header)
    if not match:
        return block_lines

    condition = match.group(1).strip()
    then_line = block_lines[1].strip()
    else_line = block_lines[2].strip()

    then_goto = PURE_GOTO_RE.match(then_line)
    if condition in ("T", "t") and then_goto:
        return [block_lines[1]]

    if condition in ("nil", "(nil)"):
        if else_line == "(progn" and block_lines[-2].strip() == ")" and block_lines[-1].strip() == ")":
            return block_lines[3:-2]
        else_goto = PURE_GOTO_RE.match(else_line)
        if else_goto:
            return [block_lines[2]]

    if then_goto and PURE_GOTO_RE.match(else_line):
        if then_goto.group(1) == PURE_GOTO_RE.match(else_line).group(1):
            return [block_lines[1]]

    return block_lines


def clean_final_lsp_lines(lines: list[str]) -> list[str]:
    cleaned: list[str] = []
    index = 0
    referenced_blocks: set[str] = set()

    for line in lines:
        referenced_blocks.update(re.findall(r"\(goto (:L_[0-9A-F]+)\)", line))
        for branch_match in BRANCH_LABEL_RE.finditer(line):
            referenced_blocks.add(branch_match.group(2))

    while index < len(lines):
        stripped = lines[index].strip()

        if not stripped:
            if cleaned and cleaned[-1]:
                cleaned.append("")
            index += 1
            continue

        if stripped.startswith(";;; ["):
            index += 1
            continue

        if stripped.startswith(";"):
            if stripped.startswith("; preds=") or stripped.startswith("; meta-u16") or stripped.startswith("; :"):
                index += 1
                continue
            index += 1
            continue

        if stripped.startswith("(block "):
            block_match = re.match(r"^\(block ([^ )]+)$", stripped)
            block_name = block_match.group(1) if block_match else None
            end = index + 1
            block_body: list[str] = []
            while end < len(lines) and lines[end].strip() != "  )" and lines[end].strip() != ")":
                candidate = lines[end].strip()
                if candidate and not candidate.startswith(";"):
                    block_body.append(candidate)
                end += 1
            next_significant = end + 1
            while next_significant < len(lines) and not lines[next_significant].strip():
                next_significant += 1
            closes_function = next_significant < len(lines) and lines[next_significant].strip() == ")"
            if not block_body and block_name not in referenced_blocks and not closes_function:
                index = end + 1 if end < len(lines) else end
                continue

        goto_match = PURE_GOTO_RE.match(stripped)
        if goto_match:
            target = goto_match.group(1)
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            while lookahead < len(lines) and lines[lookahead].strip().startswith(";"):
                lookahead += 1
            if lookahead < len(lines) and lines[lookahead].strip() == f"(block {target}":
                index += 1
                continue
            if lookahead < len(lines) and lines[lookahead].strip() == f"; {target}":
                index = lookahead + 1
                continue

        if stripped.startswith("(if "):
            end = form_span(lines, index)
            cleaned.extend(simplify_if_block(lines[index : end + 1]))
            index = end + 1
            continue

        if stripped == "(cond":
            end = form_span(lines, index)
            cleaned.extend(simplify_cond_block(lines[index : end + 1]))
            index = end + 1
            continue

        if stripped == "nil":
            prev = cleaned[-1].strip() if cleaned else ""
            nxt = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if prev.startswith("(cond") or prev.startswith("(case-dispatch") or prev.startswith("(if ") or nxt == ")":
                index += 1
                continue

        cleaned.append(lines[index])
        index += 1

    return cleaned


def collapse_final_block_redirects(lines: list[str]) -> list[str]:
    def rewrite_targets(text: str, redirects: dict[str, str]) -> str:
        def resolve(name: str) -> str:
            seen: set[str] = set()
            while name in redirects and name not in seen:
                seen.add(name)
                name = redirects[name]
            return name

        text = re.sub(
            r"\(goto (:L_[0-9A-F]+)\)",
            lambda match: f"(goto {resolve(match.group(1))})",
            text,
        )
        branch_match = BRANCH_LABEL_RE.match(text)
        if branch_match:
            target = resolve(branch_match.group(2))
            text = f"{branch_match.group(1)}{target}{branch_match.group(3)}"
        return text

    output: list[str] = []
    index = 0

    while index < len(lines):
        if not lines[index].startswith("(defun "):
            output.append(lines[index])
            index += 1
            continue

        function_lines = [lines[index]]
        index += 1
        while index < len(lines):
            function_lines.append(lines[index])
            if lines[index] == ")":
                index += 1
                break
            index += 1

        if len(function_lines) <= 2:
            output.extend(function_lines)
            continue

        header = function_lines[0]
        footer = function_lines[-1]
        body = function_lines[1:-1]
        blocks: list[tuple[str, list[str]]] = []
        cursor = 0
        while cursor < len(body):
            line = body[cursor]
            block_match = re.match(r"^  \(block ([^\s)]+)", line)
            if not block_match:
                blocks.append(("", [line]))
                cursor += 1
                continue
            name = block_match.group(1)
            block_lines = [line]
            cursor += 1
            while cursor < len(body):
                block_lines.append(body[cursor])
                if body[cursor] == "  )":
                    cursor += 1
                    break
                cursor += 1
            blocks.append((name, block_lines))

        redirects: dict[str, str] = {}
        ordered_names = [name for name, _ in blocks if name]
        for block_index, (name, block_lines) in enumerate(blocks):
            if not name or name == ":entry":
                continue
            inner = block_lines[1:-1]
            meaningful = [line.strip() for line in inner if line.strip() and not line.strip().startswith(";")]
            if not meaningful:
                next_name = None
                for future_name in ordered_names[ordered_names.index(name) + 1 :]:
                    next_name = future_name
                    break
                if next_name:
                    redirects[name] = next_name
                continue
            if len(meaningful) == 1:
                goto_match = PURE_GOTO_RE.match(meaningful[0])
                if goto_match:
                    redirects[name] = goto_match.group(1)

        changed = True
        while changed:
            changed = False
            for name, target in list(redirects.items()):
                final_target = redirects.get(target)
                if final_target and final_target != target:
                    redirects[name] = final_target
                    changed = True

        rewritten_blocks: list[str] = [header]
        for name, block_lines in blocks:
            if not name:
                rewritten_blocks.extend(rewrite_targets(line, redirects) for line in block_lines)
                continue
            if name in redirects:
                continue
            rewritten_blocks.append(block_lines[0])
            for line in block_lines[1:-1]:
                rewritten_blocks.append(rewrite_targets(line, redirects))
            rewritten_blocks.append(block_lines[-1])
        rewritten_blocks.append(footer)
        output.extend(rewritten_blocks)

    return output


def collapse_final_simple_blocks(lines: list[str]) -> list[str]:
    output: list[str] = []
    index = 0

    while index < len(lines):
        if not lines[index].startswith("(defun "):
            output.append(lines[index])
            index += 1
            continue

        function_lines = [lines[index]]
        index += 1
        while index < len(lines):
            function_lines.append(lines[index])
            if lines[index] == ")":
                index += 1
                break
            index += 1

        if len(function_lines) <= 2:
            output.extend(function_lines)
            continue

        header = function_lines[0]
        footer = function_lines[-1]
        body = function_lines[1:-1]
        blocks: list[tuple[str, list[str]]] = []
        cursor = 0
        while cursor < len(body):
            line = body[cursor]
            block_match = re.match(r"^  \(block ([^\s)]+)", line)
            if not block_match:
                blocks.append(("", [line]))
                cursor += 1
                continue
            name = block_match.group(1)
            block_lines = [line]
            cursor += 1
            while cursor < len(body):
                block_lines.append(body[cursor])
                if body[cursor] == "  )":
                    cursor += 1
                    break
                cursor += 1
            blocks.append((name, block_lines))

        names = [name for name, _ in blocks if name]
        preds: dict[str, set[str]] = {name: set() for name in names}
        succs: dict[str, set[str]] = {name: set() for name in names}

        def block_meaningful_lines(block_lines: list[str]) -> list[str]:
            return [
                line.strip()
                for line in block_lines[1:-1]
                if line.strip() and not line.strip().startswith(";")
            ]

        for block_index, (name, block_lines) in enumerate(blocks):
            if not name:
                continue
            block_succs: set[str] = set()
            for line in block_lines[1:-1]:
                block_succs.update(GOTO_LABEL_RE.findall(line))
                branch_match = BRANCH_LABEL_RE.match(line)
                if branch_match:
                    block_succs.add(branch_match.group(2))
            if not block_succs and block_index + 1 < len(blocks) and blocks[block_index + 1][0]:
                block_succs.add(blocks[block_index + 1][0])
            succs[name] = {target for target in block_succs if target in preds}
            for target in succs[name]:
                preds[target].add(name)

        removed_blocks: set[str] = set()
        for block_index, (name, block_lines) in enumerate(blocks):
            if not name or name == ":entry":
                continue
            meaningful = block_meaningful_lines(block_lines)
            if len(meaningful) != 1:
                continue
            if len(preds.get(name, set())) != 1:
                continue

            pred_name = next(iter(preds[name]))
            pred_index = next((i for i, (other_name, _) in enumerate(blocks) if other_name == pred_name), None)
            if pred_index is None:
                continue
            pred_lines = blocks[pred_index][1]
            pred_meaningful = [
                line.strip()
                for line in pred_lines[1:-1]
                if line.strip() and not line.strip().startswith(";")
            ]
            if not pred_meaningful:
                continue
            goto_match = PURE_GOTO_RE.match(pred_meaningful[-1])
            if not goto_match or goto_match.group(1) != name:
                continue

            replacement = meaningful[0]
            new_pred_lines = list(pred_lines)
            for line_index in range(len(new_pred_lines) - 2, 0, -1):
                if new_pred_lines[line_index].strip() and not new_pred_lines[line_index].strip().startswith(";"):
                    if PURE_GOTO_RE.match(new_pred_lines[line_index].strip()):
                        indent = new_pred_lines[line_index][: len(new_pred_lines[line_index]) - len(new_pred_lines[line_index].lstrip())]
                        new_pred_lines[line_index] = f"{indent}{replacement}"
                        blocks[pred_index] = (pred_name, new_pred_lines)
                        removed_blocks.add(name)
                    break

        rewritten_function = [header]
        for name, block_lines in blocks:
            if name and name in removed_blocks:
                continue
            rewritten_function.extend(block_lines)
        rewritten_function.append(footer)
        output.extend(rewritten_function)

    return output


def remove_unreachable_final_blocks(lines: list[str]) -> list[str]:
    output: list[str] = []
    index = 0

    while index < len(lines):
        if not lines[index].startswith("(defun "):
            output.append(lines[index])
            index += 1
            continue

        function_lines = [lines[index]]
        index += 1
        while index < len(lines):
            function_lines.append(lines[index])
            if lines[index] == ")":
                index += 1
                break
            index += 1

        if len(function_lines) <= 2:
            output.extend(function_lines)
            continue

        header = function_lines[0]
        footer = function_lines[-1]
        body = function_lines[1:-1]
        blocks: list[tuple[str, list[str]]] = []
        cursor = 0
        while cursor < len(body):
            line = body[cursor]
            block_match = re.match(r"^  \(block ([^\s)]+)", line)
            if not block_match:
                blocks.append(("", [line]))
                cursor += 1
                continue
            name = block_match.group(1)
            block_lines = [line]
            cursor += 1
            while cursor < len(body):
                block_lines.append(body[cursor])
                if body[cursor] == "  )":
                    cursor += 1
                    break
                cursor += 1
            blocks.append((name, block_lines))

        preds: dict[str, set[str]] = {name: set() for name, _ in blocks if name}

        def meaningful(block_lines: list[str]) -> list[str]:
            return [
                line.strip()
                for line in block_lines[1:-1]
                if line.strip() and not line.strip().startswith(";")
            ]

        for name, block_lines in blocks:
            if not name:
                continue
            for line in block_lines[1:-1]:
                for target in GOTO_LABEL_RE.findall(line):
                    if target in preds:
                        preds[target].add(name)
                branch_match = BRANCH_LABEL_RE.match(line)
                if branch_match and branch_match.group(2) in preds:
                    preds[branch_match.group(2)].add(name)

        remove_names: set[str] = set()
        for block_index, (name, block_lines) in enumerate(blocks):
            if not name or name == ":entry":
                continue
            if preds.get(name):
                continue
            if block_index == 0:
                continue
            prev_name, prev_lines = blocks[block_index - 1]
            if not prev_name:
                continue
            prev_meaningful = meaningful(prev_lines)
            if not prev_meaningful:
                continue
            if PURE_GOTO_RE.match(prev_meaningful[-1]):
                remove_names.add(name)

        rewritten = [header]
        for name, block_lines in blocks:
            if name and name in remove_names:
                continue
            rewritten.extend(block_lines)
        rewritten.append(footer)
        output.extend(rewritten)

    return output


def simplify_final_lsp_lines(lines: list[str]) -> list[str]:
    simplified: list[str] = []
    index = 0

    while index < len(lines):
        stripped = lines[index].strip()

        branch_match = re.match(r"^(\s*)\(branch-if (.+) ([^ )]+)\)$", lines[index])
        if branch_match:
            indent, condition, target = branch_match.groups()
            if condition in ("nil", "(nil)"):
                simplified.append(f"{indent}(goto {target})")
            elif condition in ("T", "t"):
                simplified.append(f"{indent}(goto {target})")
            else:
                simplified.append(lines[index])
            index += 1
            continue

        if stripped.startswith("(if "):
            if index + 3 < len(lines):
                first = re.match(r"^(\s*)\(if (.+)\)$", lines[index])
                then_goto = re.match(r"^\s*\(goto ([^ )]+)\)$", lines[index + 1])
                else_goto = re.match(r"^\s*\(goto ([^ )]+)\)$", lines[index + 2])
                closing = lines[index + 3].strip() == ")"
                if first and then_goto and else_goto and closing:
                    indent, condition = first.groups()
                    if then_goto.group(1) == else_goto.group(1):
                        simplified.append(f"{indent}(goto {then_goto.group(1)})")
                        index += 4
                        continue
                    if condition in ("T", "t"):
                        simplified.append(f"{indent}(goto {then_goto.group(1)})")
                        index += 4
                        continue
                    if condition in ("nil", "(nil)"):
                        simplified.append(f"{indent}(goto {else_goto.group(1)})")
                        index += 4
                        continue

        if stripped.startswith("(if T") or stripped.startswith("(if t"):
            if index + 1 < len(lines):
                next_goto = re.match(r"^\s*\(goto ([^ )]+)\)$", lines[index + 1])
                if next_goto:
                    indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
                    simplified.append(f"{indent}(goto {next_goto.group(1)})")
                    depth = 1
                    index += 1
                    while index < len(lines) and depth > 0:
                        depth += lines[index].count("(") - lines[index].count(")")
                        index += 1
                    continue

        if stripped.startswith("(if nil") or stripped.startswith("(if (nil)"):
            if index + 1 < len(lines):
                depth = 1
                cursor = index + 1
                else_start: int | None = None
                while cursor < len(lines):
                    depth += lines[cursor].count("(") - lines[cursor].count(")")
                    if lines[cursor].strip() == "(progn" and depth == 2:
                        else_start = cursor
                    if depth == 0:
                        break
                    cursor += 1
                if else_start is not None:
                    for line in lines[else_start + 1 : cursor - 1]:
                        simplified.append(line)
                    index = cursor + 1
                    continue

        if stripped == "nil":
            prev = simplified[-1].strip() if simplified else ""
            nxt = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if prev.startswith("(cond") or prev.startswith("(case-dispatch") or nxt == ")":
                index += 1
                continue

        simplified.append(lines[index])
        index += 1

    return simplified


def rename_function_headers(lines: list[str], defun_names: dict[int, str]) -> list[str]:
    renamed: list[str] = []
    for line in lines:
        match = DEFUN_HEADER_RE.match(line)
        if match:
            offset = int(match.group(1), 16)
            name = defun_names.get(offset)
            if name:
                line = f"(defun {name} (&rest args){match.group(2)}"
        renamed.append(resolve_call_targets(line, defun_names))
    return renamed


def format_named_target(target: str, defun_names: dict[int, str]) -> str:
    if not target.startswith("0x"):
        return target
    name = defun_names.get(int(target[2:], 16))
    return name if name else f":L_{target[2:]}"


def rewrite_named_control_target(line: str, defun_names: dict[int, str]) -> str:
    branch_match = BRANCH_IF_RE.match(line)
    if branch_match:
        indent, condition, target = branch_match.groups()
        return f"{indent}(branch-if {condition} {format_named_target(target, defun_names)})"

    goto_match = GOTO_RE.match(line)
    if goto_match:
        indent, target = goto_match.groups()
        return f"{indent}(goto {format_named_target(target, defun_names)})"

    return line


def split_top_level_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    escape = False

    for char in text:
        if in_string:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            current.append(char)
            continue
        if char == "(":
            depth += 1
            current.append(char)
            continue
        if char == ")":
            depth -= 1
            current.append(char)
            continue
        if char.isspace() and depth == 0:
            if current:
                tokens.append("".join(current).strip())
                current = []
            continue
        current.append(char)

    if current:
        tokens.append("".join(current).strip())
    return [token for token in tokens if token]


def parse_cond_clause(line: str) -> tuple[str, str] | None:
    match = COND_CLAUSE_RE.match(line)
    if not match:
        return None
    return match.group(1), match.group(2)


def rewrite_case_dispatch(lines: list[str]) -> list[str]:
    rewritten: list[str] = []
    index = 0

    while index < len(lines):
        if lines[index].strip() != "(cond":
            rewritten.append(lines[index])
            index += 1
            continue

        end = index + 1
        clauses: list[tuple[str, str]] = []
        while end < len(lines) and lines[end].strip() != ")":
            parsed = parse_cond_clause(lines[end])
            if parsed is None:
                break
            clauses.append(parsed)
            end += 1

        if end >= len(lines) or lines[end].strip() != ")" or len(clauses) < 2:
            rewritten.append(lines[index])
            index += 1
            continue

        non_default = [(cond, target) for cond, target in clauses if cond not in ("t", "T", "nil", "NIL")]
        default_clause = next(((cond, target) for cond, target in clauses if cond in ("t", "T")), None)
        if len(non_default) < 2:
            rewritten.extend(lines[index : end + 1])
            index = end + 1
            continue

        shape: tuple[str, str] | None = None
        cases: list[tuple[str, str]] = []
        valid = True
        for cond, target in non_default:
            if not (cond.startswith("(") and cond.endswith(")")):
                valid = False
                break
            tokens = split_top_level_tokens(cond[1:-1].strip())
            if len(tokens) != 3:
                valid = False
                break
            head = tokens[0]
            selector = tokens[1]
            key = tokens[-1]
            if shape is None:
                shape = (head, selector)
            elif shape != (head, selector):
                valid = False
                break
            cases.append((key, target))

        if not valid or shape is None:
            rewritten.extend(lines[index : end + 1])
            index = end + 1
            continue

        indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
        test_name, selector = shape
        rewritten.append(f"{indent}(case-dispatch {selector} :test {test_name}")
        for key, target in cases:
            rewritten.append(f"{indent}  ({key} (goto {target}))")
        if default_clause is not None:
            rewritten.append(f"{indent}  (t (goto {default_clause[1]}))")
        rewritten.append(f"{indent})")
        index = end + 1

    return rewritten


def collect_control_targets(data: bytes) -> tuple[set[int], set[int]]:
    targets: set[int] = set()
    function_offsets: set[int] = set()
    offset = 0

    while offset < len(data):
        try:
            next_offset, kind, payload = parse_semantic_instruction(data, offset)
        except FasDisasmMinError:
            break

        if kind == "DEFUN":
            function_offsets.add(offset)
        elif kind in ("BRANCH", "GOTO"):
            targets.add(int(payload["target"]))

        if next_offset <= offset:
            break
        offset = next_offset

    return targets, function_offsets


def simplify_labels_and_gotos(lines: list[str]) -> list[str]:
    collapsed: list[str] = []
    index = 0
    while index < len(lines):
        goto_match = GOTO_LABEL_RE.fullmatch(lines[index].strip())
        next_label = LABEL_RE.match(lines[index + 1]) if index + 1 < len(lines) else None
        if goto_match and next_label and goto_match.group(1) == next_label.group(2):
            index += 1
            continue
        collapsed.append(lines[index])
        index += 1

    return collapsed


def build_basic_blocks(lines: list[str]) -> list[str]:
    synthetic_counter = 0

    def next_synthetic_name() -> str:
        nonlocal synthetic_counter
        synthetic_counter += 1
        return f":B_{synthetic_counter:04X}"

    def split_terminated_blocks(blocks: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
        split_blocks: list[tuple[str, list[str]]] = []

        def case_dispatch_end(block_lines: list[str], start: int) -> int:
            depth = 0
            for index in range(start, len(block_lines)):
                depth += block_lines[index].count("(") - block_lines[index].count(")")
                if depth == 0:
                    return index
            return len(block_lines) - 1

        for name, block_lines in blocks:
            if not block_lines:
                split_blocks.append((name, []))
                continue

            current_name = name
            remaining = list(block_lines)
            while remaining:
                split_at: int | None = None
                split_end: int | None = None
                for index, line in enumerate(remaining):
                    if line.startswith("  (goto ") or line.startswith("  (branch-if "):
                        if index + 1 < len(remaining):
                            split_at = index
                            split_end = index
                        break
                    if line.startswith("  (case-dispatch "):
                        end = case_dispatch_end(remaining, index)
                        if end + 1 < len(remaining):
                            split_at = index
                            split_end = end
                        break
                if split_at is None or split_end is None:
                    split_blocks.append((current_name, remaining))
                    break

                split_blocks.append((current_name, remaining[: split_end + 1]))
                remaining = remaining[split_end + 1 :]
                current_name = next_synthetic_name()

        return split_blocks

    def rewrite_loop_form(block_name: str, block_lines: list[str]) -> list[str]:
        if len(block_lines) < 7:
            return block_lines

        first = block_lines[0].strip()
        second = block_lines[1].strip()
        third = block_lines[2].strip()
        penultimate = block_lines[-2].strip()
        last = block_lines[-1].strip()

        if not first.startswith("(if ") or third != "(progn" or penultimate != ")" or last != ")":
            return block_lines

        true_goto = PURE_GOTO_RE.match(second)
        back_goto = PURE_GOTO_RE.match(block_lines[-3].strip()) if len(block_lines) >= 3 else None
        if not true_goto or not back_goto:
            return block_lines

        condition = first[len("(if ") :].rstrip()
        exit_target = true_goto.group(1)
        loop_target = back_goto.group(1)
        body = block_lines[3:-3]

        if loop_target == block_name and exit_target != block_name:
            rewritten = [f"  (until {condition}"]
            rewritten.extend(body)
            rewritten.append("  )")
            return rewritten

        if exit_target == block_name and loop_target != block_name:
            rewritten = [f"  (while {condition}"]
            rewritten.extend(body)
            rewritten.append("  )")
            return rewritten

        return block_lines

    def fold_branch_fallthrough_blocks(blocks: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
        folded: list[tuple[str, list[str]]] = []
        index = 0

        while index < len(blocks):
            name, block_lines = blocks[index]
            if index + 1 >= len(blocks):
                folded.append((name, block_lines))
                index += 1
                continue

            next_name, next_lines = blocks[index + 1]
            if not next_name.startswith(":B_"):
                folded.append((name, block_lines))
                index += 1
                continue

            last_control_index = None
            last_control_match: re.Match[str] | None = None
            last_control_kind: str | None = None
            for cursor in range(len(block_lines) - 1, -1, -1):
                candidate = block_lines[cursor].strip()
                if not candidate or candidate.startswith(";"):
                    continue
                branch_match = BRANCH_IF_RE.match(block_lines[cursor])
                if branch_match:
                    last_control_index = cursor
                    last_control_match = branch_match
                    last_control_kind = "branch"
                elif block_lines[cursor].strip().startswith("(case-dispatch "):
                    last_control_index = cursor
                    last_control_kind = "case"
                break

            if last_control_index is None or last_control_kind is None:
                folded.append((name, block_lines))
                index += 1
                continue

            run_end = index + 1
            fallback_body: list[str] = []
            while run_end < len(blocks) and blocks[run_end][0].startswith(":B_"):
                fallback_body.extend(blocks[run_end][1])
                run_end += 1

            if not fallback_body:
                folded.append((name, block_lines))
                index += 1
                continue

            merged = list(block_lines[:last_control_index])
            indent = block_lines[last_control_index][: len(block_lines[last_control_index]) - len(block_lines[last_control_index].lstrip())]
            if last_control_kind == "branch" and last_control_match is not None:
                _, condition, target = last_control_match.groups()
                merged.append(f"{indent}(if {condition}")
                merged.append(f"{indent}  (goto {target})")
                merged.append(f"{indent}  (progn")
                for line in fallback_body:
                    merged.append(f"{indent}    {line.lstrip()}")
                merged.append(f"{indent}  )")
                merged.append(f"{indent})")
            else:
                merged.append(f"{indent}(progn")
                for line in fallback_body:
                    merged.append(f"{indent}  {line.lstrip()}")
                merged.append(f"{indent})")
            folded.append((name, merged))
            index = run_end

        return folded

    def absorb_synthetic_blocks(blocks: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
        absorbed: list[tuple[str, list[str]]] = []
        for name, block_lines in blocks:
            if name.startswith(":B_") and absorbed:
                prev_name, prev_lines = absorbed[-1]
                absorbed[-1] = (prev_name, prev_lines + block_lines)
                continue
            absorbed.append((name, block_lines))
        return absorbed

    def referenced_targets(block_lines: list[str]) -> set[str]:
        targets: set[str] = set()
        for line in block_lines:
            targets.update(GOTO_LABEL_RE.findall(line))
            branch_match = BRANCH_LABEL_RE.match(line)
            if branch_match:
                targets.add(branch_match.group(2))
        return targets

    def rewrite_block_targets(block_lines: list[str], old: str, new: str) -> list[str]:
        rewritten: list[str] = []
        for line in block_lines:
            line = re.sub(rf"\(goto {re.escape(old)}\)", f"(goto {new})", line)
            branch_match = BRANCH_LABEL_RE.match(line)
            if branch_match and branch_match.group(2) == old:
                line = f"{branch_match.group(1)}{new}{branch_match.group(3)}"
            rewritten.append(line)
        return rewritten

    def simplify_function_blocks(blocks: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
        changed = True
        while changed:
            changed = False
            names = [name for name, _ in blocks]
            entry_name = names[0] if names else None

            preds: dict[str, set[str]] = {name: set() for name in names}
            for index, (name, block_lines) in enumerate(blocks):
                next_name = names[index + 1] if index + 1 < len(names) else None
                succs = referenced_targets(block_lines)
                if not succs and next_name:
                    succs.add(next_name)
                for succ in succs:
                    if succ in preds:
                        preds[succ].add(name)

            for index, (name, block_lines) in enumerate(blocks):
                if name == entry_name:
                    continue
                next_name = names[index + 1] if index + 1 < len(names) else None
                stripped = [line.strip() for line in block_lines if line.strip()]
                meaningful = [
                    line
                    for line in stripped
                    if not line.startswith(";") and line != "nil" and line != "(nil)"
                ]
                redirect_target: str | None = None
                if not meaningful and next_name:
                    redirect_target = next_name
                elif len(meaningful) == 1:
                    goto_match = PURE_GOTO_RE.match(meaningful[0])
                    if goto_match:
                        redirect_target = goto_match.group(1)

                if not redirect_target:
                    continue

                new_blocks: list[tuple[str, list[str]]] = []
                for other_name, other_lines in blocks:
                    if other_name == name:
                        continue
                    new_blocks.append((other_name, rewrite_block_targets(other_lines, name, redirect_target)))
                blocks = new_blocks
                changed = True
                break

        return blocks

    def emit_function(header: str, blocks: list[tuple[str, list[str]]], output: list[str]) -> None:
        blocks = split_terminated_blocks(blocks)
        blocks = fold_branch_fallthrough_blocks(blocks)
        blocks = absorb_synthetic_blocks(blocks)
        blocks = simplify_function_blocks(blocks)
        names = [name for name, _ in blocks]
        preds: dict[str, set[str]] = {name: set() for name in names}
        succs_map: dict[str, set[str]] = {name: set() for name in names}

        for index, (name, block_lines) in enumerate(blocks):
            next_name = names[index + 1] if index + 1 < len(names) else None
            succs = referenced_targets(block_lines)
            if not succs and next_name:
                succs.add(next_name)
            succs_map[name] = {succ for succ in succs if succ in preds}
            for succ in succs_map[name]:
                preds[succ].add(name)

        output.append(header)
        for index, (name, block_lines) in enumerate(blocks):
            next_name = blocks[index + 1][0] if index + 1 < len(blocks) else None
            if next_name and block_lines:
                goto_match = GOTO_LABEL_RE.fullmatch(block_lines[-1].strip())
                if goto_match and goto_match.group(1) == next_name:
                    block_lines = block_lines[:-1]
            block_lines = rewrite_loop_form(name, block_lines)
            output.append(f"  (block {name}")
            preds_text = " ".join(sorted(preds.get(name, set()))) or "-"
            succs_text = " ".join(sorted(succs_map.get(name, set()))) or "-"
            output.append(f"    ; preds={preds_text} succs={succs_text}")
            for line in block_lines:
                output.append(f"    {line[2:]}" if line.startswith("  ") else f"    {line}")
            output.append("  )")
        output.append(")")

    output: list[str] = []
    header: str | None = None
    current_name: str | None = None
    current_lines: list[str] = []
    blocks: list[tuple[str, list[str]]] = []
    function_paren_depth = 0

    for line in lines:
        stripped = line.strip()
        line_delta = line.count("(") - line.count(")")

        if stripped.startswith("(defun "):
            if header is not None:
                current_lines.append(line)
                function_paren_depth += line_delta
                continue
            header = line
            current_name = ":entry"
            function_paren_depth = line_delta
            continue

        if header is None:
            output.append(line)
            continue

        if stripped == ")" and function_paren_depth == 1:
            blocks.append((current_name or ":entry", current_lines))
            emit_function(header, blocks, output)
            header = None
            current_name = None
            current_lines = []
            blocks = []
            function_paren_depth = 0
            continue

        label_match = LABEL_RE.match(line)
        if label_match and function_paren_depth == 1:
            blocks.append((current_name or ":entry", current_lines))
            current_name = label_match.group(2)
            current_lines = []
            continue

        current_lines.append(line)
        function_paren_depth += line_delta

    if header is not None:
        blocks.append((current_name or ":entry", current_lines))
        emit_function(header, blocks, output)

    return output


def rewrite_control_flow(lines: list[str], defun_names: dict[int, str]) -> list[str]:
    rewritten: list[str] = []
    index = 0

    while index < len(lines):
        match = BRANCH_IF_RE.match(lines[index])
        if not match:
            rewritten.append(rewrite_named_control_target(lines[index], defun_names))
            index += 1
            continue

        chain: list[tuple[str, str, str]] = []
        cursor = index
        while cursor < len(lines):
            chain_match = BRANCH_IF_RE.match(lines[cursor])
            if not chain_match:
                break
            chain.append(chain_match.groups())
            cursor += 1

        if len(chain) >= 2:
            default_target: str | None = None
            if cursor < len(lines):
                goto_match = GOTO_RE.match(lines[cursor])
                if goto_match:
                    default_target = goto_match.group(2)
                    cursor += 1

            indent = chain[0][0]
            rewritten.append(f"{indent}(cond")
            for _, condition, target in chain:
                rewritten.append(
                    f"{indent}  ({condition} (goto {format_named_target(target, defun_names)}))"
                )
            if default_target is not None:
                rewritten.append(f"{indent}  (t (goto {format_named_target(default_target, defun_names)}))")
            rewritten.append(f"{indent})")
            index = cursor
            continue

        indent, condition, target = match.groups()
        body: list[str] = []
        cursor = index + 1
        terminal_goto: str | None = None

        while cursor < len(lines):
            line = lines[cursor]
            if line.startswith("(defun ") or line.startswith(";;; [") or line == ")":
                break
            if BRANCH_IF_RE.match(line):
                break
            goto_match = GOTO_RE.match(line)
            if goto_match:
                terminal_goto = goto_match.group(2)
                break
            body.append(rewrite_named_control_target(line, defun_names))
            cursor += 1

        if terminal_goto is None:
            rewritten.append(rewrite_named_control_target(lines[index], defun_names))
            index += 1
            continue

        true_target = format_named_target(target, defun_names)
        false_target = format_named_target(terminal_goto, defun_names)

        if terminal_goto == target:
            rewritten.append(f"{indent}(unless {condition}")
            for body_line in body:
                normalized = body_line[len(indent) :] if body_line.startswith(indent) else body_line.lstrip()
                rewritten.append(f"{indent}  {normalized}")
            rewritten.append(f"{indent})")
            index = cursor + 1
            continue

        rewritten.append(f"{indent}(if {condition}")
        rewritten.append(f"{indent}  (goto {true_target})")
        if body:
            rewritten.append(f"{indent}  (progn")
            for body_line in body:
                normalized = body_line[len(indent) :] if body_line.startswith(indent) else body_line.lstrip()
                rewritten.append(f"{indent}    {normalized}")
            rewritten.append(f"{indent}    (goto {false_target})")
            rewritten.append(f"{indent}  )")
        else:
            rewritten.append(f"{indent}  (goto {false_target})")
        rewritten.append(f"{indent})")
        index = cursor + 1

    return rewritten


def build_stream_semantics(data: bytes, label: str) -> list[str]:
    stack: list[object] = []
    globals_map: dict[int, object] = {}
    locals_map: dict[int, object] = {}
    lines = [f"[{label}]"]
    offset = 0

    while offset < len(data):
        try:
            next_offset, kind, payload = parse_semantic_instruction(data, offset)
        except FasDisasmMinError as exc:
            lines.append(f"{offset:05d}  SEMANTIC_ERROR {exc}")
            lines.append(f"{offset:05d}  {data[offset:].hex(' ')}")
            break

        if kind == "DEFUN":
            lines.append(
                f"{offset:05d}  DEFUN locals={payload['locals']} args={payload['args_min']}..{payload['args_max']}"
            )
            locals_map = {}
        elif kind == "END_DEFUN":
            lines.append(f"{offset:05d}  END_DEFUN")
        elif kind == "PUSH":
            stack.append(payload["value"])
            lines.append(f"{offset:05d}  PUSH {render_value(payload['value'])}")
        elif kind == "PUSH_GVAR_VALUE":
            value = globals_map.get(payload["index"], f"G[{payload['index']}]")
            stack.append(value)
            lines.append(f"{offset:05d}  PUSH_GVAR_VALUE {render_value(value)}")
        elif kind == "PUSH_GVAR_ITEM":
            value = globals_map.get(payload["index"], f"G[{payload['index']}]")
            stack.append(value)
            lines.append(f"{offset:05d}  PUSH_GVAR_ITEM {render_value(value)}")
        elif kind == "PUSH_STREAM_REF":
            value = f"STREAM[{payload['stream_id']}:{payload['index']}]"
            stack.append(value)
            lines.append(f"{offset:05d}  PUSH_STREAM_REF {value}")
        elif kind == "SETQ":
            value = stack.pop() if stack else "<stack-empty>"
            globals_map[payload["index"]] = value
            lines.append(f"{offset:05d}  SET G[{payload['index']}] = {render_value(value)}")
        elif kind == "POP":
            value = stack.pop() if stack else "<stack-empty>"
            lines.append(f"{offset:05d}  POP {render_value(value)}")
        elif kind == "DUP":
            value = stack[-1] if stack else "<stack-empty>"
            stack.append(value)
            lines.append(f"{offset:05d}  DUP {render_value(value)}")
        elif kind == "CONS":
            right = stack.pop() if stack else "<stack-empty>"
            left = stack.pop() if stack else "<stack-empty>"
            value = f"(cons {render_value(left)} {render_value(right)})"
            stack.append(value)
            lines.append(f"{offset:05d}  {value}")
        elif kind == "UNARY_CALL":
            operand = stack.pop() if stack else "<stack-empty>"
            value = f"({payload['name']} {render_value(operand)})"
            stack.append(value)
            lines.append(f"{offset:05d}  {value}")
        elif kind == "CALL":
            argc = int(payload["argc"])
            args: list[object] = []
            for _ in range(argc):
                args.append(stack.pop() if stack else "<stack-empty>")
            args.reverse()
            fn = globals_map.get(payload["gvar"], f"G[{payload['gvar']}]")
            expr = format_call_expression(
                render_value(fn),
                [render_value(arg) for arg in args],
            )
            stack.append(expr)
            lines.append(f"{offset:05d}  CALL {expr}")
        elif kind == "EVAL":
            argc = int(payload["argc"])
            args: list[object] = []
            for _ in range(argc):
                args.append(stack.pop() if stack else "<stack-empty>")
            args.reverse()
            form = stack.pop() if stack else "<stack-empty>"
            expr = format_call_expression(
                f"eval {render_value(form)}",
                [render_value(arg) for arg in args],
            )
            stack.append(expr)
            lines.append(f"{offset:05d}  EVAL {expr}")
        elif kind == "FUNC":
            argc = int(payload["argc"])
            target = globals_map.get(payload["gvar"], f"G[{payload['gvar']}]")
            value = (
                f"(func {render_value(target)} argc={argc} "
                f"flags=0x{int(payload['flags']):02X} extra={int(payload['extra'])})"
            )
            stack.append(value)
            lines.append(f"{offset:05d}  FUNC {value}")
        elif kind == "CALL_BY_OFFSET":
            argc = int(payload["argc"])
            args: list[object] = []
            for _ in range(argc):
                args.append(stack.pop() if stack else "<stack-empty>")
            args.reverse()
            expr = format_call_expression(
                f"call@{format_target(int(payload['target']))}",
                [render_value(arg) for arg in args],
            )
            stack.append(expr)
            lines.append(f"{offset:05d}  CALL_BY_OFFSET {expr}")
        elif kind == "CALL_VL_ARX":
            argc = int(payload["argc"])
            args: list[object] = []
            for _ in range(argc):
                args.append(stack.pop() if stack else "<stack-empty>")
            args.reverse()
            expr = format_call_expression(
                f"vl-arx@{int(payload['target'])}",
                [render_value(arg) for arg in args],
            )
            stack.append(expr)
            lines.append(f"{offset:05d}  CALL_VL_ARX {expr}")
        elif kind in ("JMP2_NOPOP", "CONTINUE_AT"):
            argc = int(payload["argc"])
            args: list[object] = []
            for _ in range(argc):
                args.append(stack.pop() if stack else "<stack-empty>")
            args.reverse()
            lines.append(
                f"{offset:05d}  {kind} -> {format_target(int(payload['target']))} "
                f"args={[render_value(arg) for arg in args]}"
            )
        elif kind == "LD_LIST":
            count = int(payload["count"])
            items: list[object] = []
            for _ in range(count):
                items.append(stack.pop() if stack else "<stack-empty>")
            items.reverse()
            value = format_call_expression("list", [render_value(item) for item in items])
            stack.append(value)
            lines.append(f"{offset:05d}  {value}")
        elif kind == "IVARS":
            module_marker = stack.pop() if stack else "<stack-empty>"
            start = int(payload["var_pos"])
            count = int(payload["init_count"])
            values: list[object] = []
            for _ in range(count):
                values.append(stack.pop() if stack else "<stack-empty>")
            values.reverse()
            for index, value in enumerate(values, start=start):
                globals_map[index] = value
            lines.append(
                f"{offset:05d}  IVARS G[{start}..{start + count - 1}] from {render_value(module_marker)}"
            )
        elif kind == "DEF_FUNC_FROM_STACK":
            name = stack.pop() if stack else "<stack-empty>"
            target = stack.pop() if stack else "<stack-empty>"
            env = stack.pop() if stack else "<stack-empty>"
            value = f"(defun-ref {render_value(name)} @ {render_value(target)} env={render_value(env)})"
            stack.append(value)
            lines.append(f"{offset:05d}  DEF_FUNC_FROM_STACK {value}")
        elif kind == "LD_STR":
            for value in payload["values"]:
                stack.append(f"\"{value}\"")
            lines.append(f"{offset:05d}  LD_STR {payload['values']!r}")
        elif kind == "LD_SYM":
            for value in payload["values"]:
                stack.append(value)
            lines.append(f"{offset:05d}  LD_SYM {payload['values']!r}")
        elif kind == "LOCAL8":
            index = int(payload["index"])
            if payload["mode"] == "get":
                value = locals_map.get(index, f"L[{index}]")
                stack.append(value)
                lines.append(f"{offset:05d}  PUSH_LOCAL {render_value(value)}")
            else:
                value = stack.pop() if stack else "<stack-empty>"
                locals_map[index] = value
                lines.append(f"{offset:05d}  SET_LOCAL L[{index}] = {render_value(value)}")
        elif kind == "LOCAL16":
            index = int(payload["index"])
            if payload["mode"] == "get":
                value = locals_map.get(index, f"L[{index}]")
                stack.append(value)
                lines.append(f"{offset:05d}  PUSH_LOCAL {render_value(value)}")
            else:
                value = stack.pop() if stack else "<stack-empty>"
                locals_map[index] = value
                lines.append(f"{offset:05d}  SET_LOCAL L[{index}] = {render_value(value)}")
        elif kind == "ARITH":
            name = str(payload["name"])
            if name in ("1+", "1-"):
                value = stack.pop() if stack else "<stack-empty>"
                expr = f"({name} {render_value(value)})"
            else:
                right = stack.pop() if stack else "<stack-empty>"
                left = stack.pop() if stack else "<stack-empty>"
                expr = f"({name} {render_value(left)} {render_value(right)})"
            stack.append(expr)
            lines.append(f"{offset:05d}  {expr}")
        elif kind == "BRANCH":
            condition = stack.pop() if stack else "<stack-empty>"
            lines.append(
                f"{offset:05d}  BRANCH if {render_value(condition)} -> {format_target(int(payload['target']))}"
            )
        elif kind == "GOTO":
            lines.append(f"{offset:05d}  GOTO -> {format_target(int(payload['target']))}")
        elif kind == "SETUP_ERROR_HANDLER":
            lines.append(f"{offset:05d}  SETUP_ERROR_HANDLER")
        elif kind == "U16":
            lines.append(f"{offset:05d}  META_U16 {payload['value']}")
        elif kind == "NOOP":
            pass
        else:
            lines.append(f"{offset:05d}  {payload['text']}")

        if next_offset <= offset:
            break
        offset = next_offset

    return lines


def build_semantic_dump(
    function_stream: bytes, resource_stream: bytes, metadata: dict[str, object]
) -> str:
    header = [
        f"kind: {metadata['kind']}",
        f"version: {metadata['version']}",
        "",
    ]
    body = build_stream_semantics(resource_stream, "resource_stream")
    body.append("")
    body.extend(build_stream_semantics(function_stream, "function_stream"))
    return "\n".join(header + body) + "\n"


def build_stream_pseudolisp(
    data: bytes, label: str, seed_globals: dict[int, object] | None = None
) -> tuple[list[str], dict[int, object]]:
    stack: list[object] = []
    globals_map: dict[int, object] = dict(seed_globals or {})
    locals_map: dict[int, object] = {}
    lines = [f";;; [{label}]"]
    control_targets, function_offsets = collect_control_targets(data)
    offset = 0
    function_depth = 0
    underflow_count = 0
    desynced = False

    def emit(text: str, body: bool = True) -> None:
        indent = "  " * (function_depth + (1 if body else 0))
        lines.append(f"{indent}{text}")

    while offset < len(data):
        if function_depth and offset in control_targets and offset not in function_offsets:
            emit(f"(label :L_{offset:04X})")

        try:
            next_offset, kind, payload = parse_semantic_instruction(data, offset)
        except FasDisasmMinError as exc:
            emit(f"; PSEUDOLISP_ERROR at {format_target(offset)}: {exc}")
            emit(f"; {data[offset: min(len(data), offset + 64)].hex(' ')}")
            break

        if kind == "RAW":
            text = str(payload["text"])
            if text.startswith("OP_0x") or text.startswith("STOP_0x"):
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: {text}")
                break

        if kind == "DEFUN":
            emit(f"(defun fn_{offset:04X} (&rest args) ; locals={payload['locals']} args={payload['args_min']}..{payload['args_max']}", body=False)
            function_depth += 1
        elif kind == "END_DEFUN":
            if function_depth:
                function_depth -= 1
                emit(")", body=False)
            else:
                emit("; UNMATCHED_END_DEFUN")
        elif kind == "PUSH":
            stack.append(payload["value"])
        elif kind == "PUSH_GVAR_VALUE":
            stack.append(globals_map.get(payload["index"], f"G[{payload['index']}]"))
        elif kind == "PUSH_GVAR_ITEM":
            stack.append(globals_map.get(payload["index"], f"G[{payload['index']}]"))
        elif kind == "PUSH_STREAM_REF":
            stack.append(f"STREAM[{payload['stream_id']}:{payload['index']}]")
        elif kind == "SETQ":
            value, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            globals_map[payload["index"]] = value
            emit(f"(setq G[{payload['index']}] {render_value(value)})")
        elif kind == "POP":
            value, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            if not is_discardable_popped_value(value):
                emit(render_value(value))
        elif kind == "DUP":
            if stack:
                stack.append(stack[-1])
            else:
                stack.append("<stack-empty>")
                underflow_count += 1
        elif kind == "CONS":
            right, u1 = safe_pop(stack)
            left, u2 = safe_pop(stack)
            underflow_count += int(u1) + int(u2)
            stack.append(f"(cons {render_value(left)} {render_value(right)})")
        elif kind == "UNARY_CALL":
            operand, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            stack.append(f"({payload['name']} {render_value(operand)})")
        elif kind == "CALL":
            argc = int(payload["argc"])
            if argc > 64:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious argc={argc} gvar={payload['gvar']}")
                break
            args: list[object] = []
            for _ in range(argc):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                args.append(value)
            args.reverse()
            fn = globals_map.get(payload["gvar"], f"G[{payload['gvar']}]")
            stack.append(
                format_call_expression(
                    render_value(fn),
                    [render_value(arg) for arg in args],
                )
            )
        elif kind == "EVAL":
            argc = int(payload["argc"])
            if argc > 64:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious eval argc={argc}")
                break
            args: list[object] = []
            for _ in range(argc):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                args.append(value)
            args.reverse()
            form, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            stack.append(
                format_call_expression(
                    f"eval {render_value(form)}",
                    [render_value(arg) for arg in args],
                )
            )
        elif kind == "FUNC":
            target = globals_map.get(payload["gvar"], f"G[{payload['gvar']}]")
            stack.append(
                f"(func {render_value(target)} argc={int(payload['argc'])} "
                f"flags=0x{int(payload['flags']):02X} extra={int(payload['extra'])})"
            )
        elif kind == "CALL_BY_OFFSET":
            argc = int(payload["argc"])
            if argc > 64:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious call@ argc={argc}")
                break
            args: list[object] = []
            for _ in range(argc):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                args.append(value)
            args.reverse()
            stack.append(
                format_call_expression(
                    f"call@{format_target(int(payload['target']))}",
                    [render_value(arg) for arg in args],
                )
            )
        elif kind == "CALL_VL_ARX":
            argc = int(payload["argc"])
            if argc > 64:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious vl-arx argc={argc}")
                break
            args: list[object] = []
            for _ in range(argc):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                args.append(value)
            args.reverse()
            stack.append(
                format_call_expression(
                    f"vl-arx@{int(payload['target'])}",
                    [render_value(arg) for arg in args],
                )
            )
        elif kind in ("JMP2_NOPOP", "CONTINUE_AT"):
            argc = int(payload["argc"])
            if argc > 64:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious jump argc={argc}")
                break
            args: list[object] = []
            for _ in range(argc):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                args.append(value)
            args.reverse()
            emit(
                format_call_expression(
                    f"{kind.lower()} {format_target(int(payload['target']))}",
                    [render_value(arg) for arg in args],
                )
            )
        elif kind == "LD_LIST":
            count = int(payload["count"])
            if count > 256:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious list count={count}")
                break
            items: list[object] = []
            for _ in range(count):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                items.append(value)
            items.reverse()
            stack.append(format_call_expression("list", [render_value(item) for item in items]))
        elif kind == "IVARS":
            module_marker, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            start = int(payload["var_pos"])
            count = int(payload["init_count"])
            if start > 10000:
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: suspicious ivars start={start} count={count}")
                break
            if count > len(stack):
                emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: ivars underflow need={count} have={len(stack)}")
                break
            values: list[object] = []
            for _ in range(count):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                values.append(value)
            values.reverse()
            emit(f"; ivars from {render_value(module_marker)}")
            for index, value in enumerate(values, start=start):
                globals_map[index] = value
                emit(f"(setq G[{index}] {render_value(value)})")
        elif kind == "LD_STR":
            for value in payload["values"]:
                stack.append(f"\"{value}\"")
        elif kind == "LD_SYM":
            for value in payload["values"]:
                stack.append(value)
        elif kind == "LOCAL8":
            index = int(payload["index"])
            if payload["mode"] == "get":
                stack.append(locals_map.get(index, f"L[{index}]"))
            else:
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                locals_map[index] = value
                emit(f"(setq L[{index}] {render_value(locals_map[index])})")
        elif kind == "LOCAL16":
            index = int(payload["index"])
            if payload["mode"] == "get":
                stack.append(locals_map.get(index, f"L[{index}]"))
            else:
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                locals_map[index] = value
                emit(f"(setq L[{index}] {render_value(locals_map[index])})")
        elif kind == "ARITH":
            name = str(payload["name"])
            if name in ("1+", "1-"):
                value, underflow = safe_pop(stack)
                underflow_count += int(underflow)
                stack.append(f"({name} {render_value(value)})")
            else:
                right, u1 = safe_pop(stack)
                left, u2 = safe_pop(stack)
                underflow_count += int(u1) + int(u2)
                stack.append(f"({name} {render_value(left)} {render_value(right)})")
        elif kind == "BRANCH":
            condition, underflow = safe_pop(stack)
            underflow_count += int(underflow)
            emit(f"(branch-if {render_value(condition)} {format_target(int(payload['target']))})")
        elif kind == "GOTO":
            emit(f"(goto {format_target(int(payload['target']))})")
        elif kind == "SETUP_ERROR_HANDLER":
            emit("(setup-error-handler)")
        elif kind == "DEF_FUNC_FROM_STACK":
            name, u1 = safe_pop(stack)
            target, u2 = safe_pop(stack)
            env, u3 = safe_pop(stack)
            underflow_count += int(u1) + int(u2) + int(u3)
            value = f"(defun-ref {render_value(name)} :offset {render_value(target)} :env {render_value(env)})"
            stack.append(value)
        elif kind == "U16":
            emit(f"; meta-u16 {payload['value']}")

        if underflow_count >= 8 and not desynced:
            emit(f"; PSEUDOLISP_DESYNC at {format_target(offset)}: repeated stack underflow ({underflow_count})")
            break

        if next_offset <= offset:
            break
        offset = next_offset

    while function_depth > 0:
        function_depth -= 1
        emit(")", body=False)

    return lines, globals_map


def build_structured_lisp_lines(
    function_stream: bytes, resource_stream: bytes
) -> tuple[list[str], list[str], dict[int, object], dict[int, object]]:
    resource_lines, resource_globals = build_stream_pseudolisp(resource_stream, "resource_stream")
    function_lines, function_globals = build_stream_pseudolisp(
        function_stream, "function_stream", seed_globals=resource_globals
    )
    defun_names = collect_defun_names(resource_lines + function_lines)
    resource_lines = build_basic_blocks(
        simplify_labels_and_gotos(
            rewrite_case_dispatch(
                rewrite_control_flow(rename_function_headers(resource_lines, defun_names), defun_names)
            )
        )
    )
    function_lines = build_basic_blocks(
        simplify_labels_and_gotos(
            rewrite_case_dispatch(
                rewrite_control_flow(rename_function_headers(function_lines, defun_names), defun_names)
            )
        )
    )
    return resource_lines, function_lines, resource_globals, function_globals


def rewrite_case_dispatch_to_cond(lines: list[str]) -> list[str]:
    rewritten: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("(case-dispatch ") or " :test " not in stripped:
            rewritten.append(lines[index])
            index += 1
            continue

        prefix = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
        inner = stripped[len("(case-dispatch ") : -1]
        selector, test_name = inner.rsplit(" :test ", 1)
        clauses: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != ")":
            clause = lines[index].strip()
            if clause.startswith("(") and clause.endswith(")"):
                clauses.append(clause[1:-1])
            index += 1
        rewritten.append(f"{prefix}(cond")
        for clause in clauses:
            key, body = clause.split(" ", 1)
            if key == "t":
                rewritten.append(f"{prefix}  (t {body})")
            else:
                rewritten.append(f"{prefix}  (({test_name} {selector} {key}) {body})")
        rewritten.append(f"{prefix})")
        if index < len(lines) and lines[index].strip() == ")":
            index += 1
    return rewritten


def build_final_lsp_lines(function_lines: list[str]) -> list[str]:
    final_lines = rewrite_case_dispatch_to_cond(function_lines)
    cleaned: list[str] = []
    for line in final_lines:
        stripped = line.strip()
        if stripped.startswith(";;; ["):
            continue
        if stripped.startswith("; preds=") or stripped.startswith("; meta-u16"):
            continue
        if "(defun-ref " in line:
            line = re.sub(r"\(defun-ref ([^ )]+) :offset \d+ :env [^)]+\)", r"\1", line)
        cleaned.append(line)
    return cleaned


def build_pseudolisp_dump(
    function_stream: bytes, resource_stream: bytes, metadata: dict[str, object]
) -> str:
    header = [
        f";;; kind: {metadata['kind']}",
        f";;; version: {metadata['version']}",
        "",
    ]
    resource_lines, function_lines, _, _ = build_structured_lisp_lines(function_stream, resource_stream)
    body = resource_lines
    body.append("")
    body.extend(function_lines)
    return "\n".join(header + body) + "\n"


def build_final_lsp_dump(
    function_stream: bytes, resource_stream: bytes, metadata: dict[str, object]
) -> str:
    resource_lines, function_lines, _, _ = build_structured_lisp_lines(function_stream, resource_stream)
    defun_names = collect_defun_names(resource_lines + function_lines)
    global_names = collect_stable_global_names(resource_lines + function_lines)
    final_lines = [
        simplify_final_lisp_line(line, defun_names, global_names)
        for line in build_final_lsp_lines(function_lines)
    ]
    final_lines = [line for line in final_lines if line]
    final_lines = simplify_final_lsp_lines(final_lines)
    final_lines = clean_final_lsp_lines(final_lines)
    final_lines = collapse_final_block_redirects(final_lines)
    final_lines = collapse_final_simple_blocks(final_lines)
    final_lines = remove_unreachable_final_blocks(final_lines)
    header = [f"; decompiled {metadata['kind']} {metadata['version']}", ""]
    return "\n".join(header + final_lines) + "\n"


def build_final_lisp_dump(
    function_stream: bytes, resource_stream: bytes, metadata: dict[str, object]
) -> str:
    return build_final_lsp_dump(function_stream, resource_stream, metadata)


def detect_file_type(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(128)

    if header.startswith(PROTECTED_LISP_SIGNATURE):
        return "protected_lisp"
    if header.startswith(VLX_SIGNATURE):
        return "vlx"
    if any(signature in header for signature in FAS_SIGNATURES):
        return "fas"
    return "unknown"


def decrypt_protected_lisp(input_path: Path, output_path: Path | None = None) -> Path:
    data = input_path.read_bytes()
    if not data.startswith(PROTECTED_LISP_SIGNATURE):
        raise FasDisasmMinError(f"{input_path} is not an AutoCAD protected LISP file")

    probe = data[len(PROTECTED_LISP_SIGNATURE) : len(PROTECTED_LISP_SIGNATURE) + 3]
    if BYTE_1A_EOF not in probe:
        raise FasDisasmMinError(f"{input_path} does not contain the protected LISP marker")

    position = len(PROTECTED_LISP_SIGNATURE) + 3
    if position >= len(data):
        raise FasDisasmMinError(f"{input_path} is truncated before the encryption key")

    key = data[position]
    position += 1
    output = bytearray()

    for in_byte in data[position:]:
        if in_byte in (BYTE_1A_EOF, BYTE_0D_CR):
            continue

        out_byte = in_byte ^ key
        if out_byte in (BYTE_1A_EOF, BYTE_0D_CR):
            out_byte = in_byte

        if out_byte == BYTE_0A_LF:
            output.append(BYTE_0D_CR)
        output.append(out_byte)

        next_key = in_byte + in_byte
        if next_key > 0xFF:
            next_key -= 0xFF
        key = next_key

    if output_path is None:
        output_path = input_path.with_name(f"{input_path.stem}_Dec{input_path.suffix}")
    output_path.write_bytes(bytes(output))
    return output_path


def split_vlx(input_path: Path, output_dir: Path | None = None) -> list[Path]:
    data = input_path.read_bytes()
    if not data.startswith(VLX_SIGNATURE):
        raise FasDisasmMinError(f"{input_path} is not a VLX file")

    if len(data) < 12:
        raise FasDisasmMinError(f"{input_path} is too short to be a valid VLX file")

    declared_size = struct.unpack_from("<I", data, len(VLX_SIGNATURE))[0]
    if declared_size > len(data):
        raise FasDisasmMinError(
            f"{input_path} declares {declared_size} bytes but file has only {len(data)}"
        )

    if output_dir is None:
        output_dir = input_path.with_suffix("")
    output_dir.mkdir(parents=True, exist_ok=True)

    cursor = len(VLX_SIGNATURE) + 4
    extracted: list[Path] = []
    used_names: set[str] = set()

    while cursor + 4 <= len(data):
        block_start = cursor
        block_size = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if block_size == 0:
            break

        if cursor + 3 > len(data):
            raise FasDisasmMinError(f"{input_path} is truncated while reading a VLX entry")

        res_type = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        name_len = data[cursor]
        cursor += 1

        if cursor + name_len > len(data):
            raise FasDisasmMinError(f"{input_path} is truncated while reading a VLX entry name")

        raw_name = data[cursor : cursor + name_len]
        cursor += name_len
        base_name = raw_name.decode("latin-1") or f"entry_{len(extracted):04d}"

        consumed = cursor - block_start
        payload_size = block_size - consumed
        if payload_size < 0 or cursor + payload_size > len(data):
            raise FasDisasmMinError(f"{input_path} has an invalid VLX block size")

        extension = VLX_TYPE_EXTENSIONS.get(res_type, f"{res_type:04x}")
        candidate_name = f"{base_name}.{extension}"
        unique_name = candidate_name
        duplicate_index = 1
        while unique_name.lower() in used_names:
            unique_name = f"{base_name}_{duplicate_index}.{extension}"
            duplicate_index += 1
        used_names.add(unique_name.lower())

        output_path = output_dir / unique_name
        output_path.write_bytes(data[cursor : cursor + payload_size])
        extracted.append(output_path)
        cursor += payload_size
        cursor = (cursor + 3) & ~3

    if not extracted:
        raise FasDisasmMinError(f"{input_path} did not contain any extractable VLX entries")

    return extracted


def process_path(input_path: Path, output_path: Path | None = None) -> tuple[int, str]:
    file_type = detect_file_type(input_path)

    if file_type == "protected_lisp":
        result = decrypt_protected_lisp(input_path, output_path)
        return 0, f"decrypted protected lisp -> {result}"

    if file_type == "vlx":
        target_dir = output_path
        extracted = split_vlx(input_path, target_dir)
        return 0, f"split vlx -> {len(extracted)} file(s) in {extracted[0].parent}"

    if file_type == "fas":
        extracted = extract_fas_like(input_path, output_path)
        metadata = extracted["metadata"]
        return (
            0,
            "extracted fas/fsl streams -> "
            f"{extracted['fct_path']} and {extracted['res_path']} "
            f"(vars: {metadata['function_stream_vars']}/{metadata['resource_stream_vars']})",
        )

    return 1, "unknown file format"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Minimal non-UI CLI for protected LISP decryption and VLX extraction."
    )
    parser.add_argument("input", help="Input file to process")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file for protected LISP or output directory for VLX",
    )
    parser.add_argument(
        "--copy-input",
        action="store_true",
        help="Copy the original input next to the generated output directory for quick inspection",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        parser.error(f"input file does not exist: {input_path}")

    output_path = Path(args.output).resolve() if args.output else None

    try:
        code, message = process_path(input_path, output_path)
        print(message)

        if code == 0 and args.copy_input and output_path is not None and output_path.is_dir():
            shutil.copy2(input_path, output_path / input_path.name)
        return code
    except FasDisasmMinError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
