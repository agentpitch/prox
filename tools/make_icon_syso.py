#!/usr/bin/env python3
"""Generate cmd/pitchprox/pitchprox_windows_amd64.syso from assets/pp_icon_256.png.
This is a self-contained resource generator so the executable icon can be regenerated
without external Windows tooling.
"""
from __future__ import annotations
import pathlib
import struct
from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parents[1]
PNG_PATH = ROOT / "assets" / "pp_icon_256.png"
ICO_PATH = ROOT / "assets" / "pp_icon.ico"
SYSO_PATH = ROOT / "cmd" / "pitchprox" / "pitchprox_windows_amd64.syso"

SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
IMAGE_REL_AMD64_ADDR32NB = 0x0003


def add(buf: bytearray, data: bytes) -> int:
    off = len(buf)
    buf.extend(data)
    return off


def pad(buf: bytearray, alignment: int = 4) -> None:
    while len(buf) % alignment:
        buf.append(0)


def patch_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off:off + 4] = struct.pack("<I", value)


def main() -> None:
    img = Image.open(PNG_PATH).convert("RGBA")
    img.save(ICO_PATH, format="ICO", sizes=SIZES)
    ico = ICO_PATH.read_bytes()

    _, icon_type, count = struct.unpack_from("<HHH", ico, 0)
    if icon_type != 1:
        raise SystemExit("unexpected ICO type")

    entries = []
    for i in range(count):
        off = 6 + i * 16
        w, h, cc, resv, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", ico, off)
        if w == 0:
            w = 256
        if h == 0:
            h = 256
        entries.append({
            "w": w,
            "h": h,
            "cc": cc,
            "res": resv,
            "planes": planes,
            "bpp": bpp,
            "size": size,
            "data": ico[offset:offset + size],
            "id": i + 1,
        })

    buf = bytearray()
    relocs: list[tuple[int, int, int]] = []

    root_off = add(buf, struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2))
    root_icon_entry_off = add(buf, struct.pack("<II", 3, 0))
    root_group_entry_off = add(buf, struct.pack("<II", 14, 0))

    icon_type_dir_off = len(buf)
    add(buf, struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries)))
    icon_entry_offs = [add(buf, struct.pack("<II", e["id"], 0)) for e in entries]

    group_type_dir_off = len(buf)
    add(buf, struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    group_entry_off = add(buf, struct.pack("<II", 1, 0))

    icon_lang_dir_offs: list[int] = []
    icon_lang_entry_offs: list[int] = []
    for _ in entries:
        d = len(buf)
        icon_lang_dir_offs.append(d)
        add(buf, struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        icon_lang_entry_offs.append(add(buf, struct.pack("<II", 0x409, 0)))

    group_lang_dir_off = len(buf)
    add(buf, struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
    group_lang_entry_off = add(buf, struct.pack("<II", 0x409, 0))

    icon_data_entry_offs = [add(buf, struct.pack("<IIII", 0, e["size"], 0, 0)) for e in entries]
    group_header = struct.pack("<HHH", 0, 1, len(entries))
    group_entries = []
    for e in entries:
        w = 0 if e["w"] == 256 else e["w"]
        h = 0 if e["h"] == 256 else e["h"]
        group_entries.append(struct.pack(
            "<BBBBHHIH",
            w,
            h,
            e["cc"],
            e["res"],
            e["planes"],
            e["bpp"],
            e["size"],
            e["id"],
        ))
    group_data = group_header + b"".join(group_entries)
    group_data_entry_off = add(buf, struct.pack("<IIII", 0, len(group_data), 0, 0))

    patch_u32(buf, root_icon_entry_off + 4, 0x80000000 | icon_type_dir_off)
    patch_u32(buf, root_group_entry_off + 4, 0x80000000 | group_type_dir_off)
    for entry_off, dir_off in zip(icon_entry_offs, icon_lang_dir_offs):
        patch_u32(buf, entry_off + 4, 0x80000000 | dir_off)
    patch_u32(buf, group_entry_off + 4, 0x80000000 | group_lang_dir_off)
    for entry_off, data_entry_off in zip(icon_lang_entry_offs, icon_data_entry_offs):
        patch_u32(buf, entry_off + 4, data_entry_off)
    patch_u32(buf, group_lang_entry_off + 4, group_data_entry_off)

    pad(buf)
    icon_data_offs: list[int] = []
    for e in entries:
        icon_data_offs.append(len(buf))
        add(buf, e["data"])
        pad(buf)
    group_data_off = len(buf)
    add(buf, group_data)
    pad(buf)

    for data_entry_off, data_off in zip(icon_data_entry_offs, icon_data_offs):
        patch_u32(buf, data_entry_off, data_off)
        relocs.append((data_entry_off, 0, IMAGE_REL_AMD64_ADDR32NB))
    patch_u32(buf, group_data_entry_off, group_data_off)
    relocs.append((group_data_entry_off, 0, IMAGE_REL_AMD64_ADDR32NB))

    section_data = bytes(buf)
    machine = 0x8664
    header_size = 20 + 40
    ptr_raw = header_size
    ptr_reloc = ptr_raw + len(section_data)
    ptr_sym = ptr_reloc + len(relocs) * 10
    characteristics = 0x40000040

    out = bytearray()
    out += struct.pack("<HHIIIHH", machine, 1, 0, ptr_sym, 1, 0, 0)
    out += b".rsrc\x00\x00\x00"
    out += struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(section_data),
        ptr_raw,
        ptr_reloc,
        0,
        len(relocs),
        0,
        characteristics,
    )
    out += section_data
    for va, symidx, typ in relocs:
        out += struct.pack("<IIH", va, symidx, typ)
    out += b".rsrc\x00\x00\x00" + struct.pack("<IhHBB", 0, 1, 0, 3, 0)
    out += struct.pack("<I", 4)
    SYSO_PATH.write_bytes(out)
    print(f"wrote {SYSO_PATH}")


if __name__ == "__main__":
    main()
