from binaryninja import *
import struct

Elf32_Rela = struct.Struct("<III")   # 12 bytes
Elf32_Sym  = struct.Struct("<IIIBBH") # 16 bytes
Elf64_Rela = struct.Struct("<QQq")   # 24 bytes
Elf64_Sym  = struct.Struct("<IBBHQQ") # 24 bytes

Elf_Sym = None
Elf_Rela = None
ELF_RELA_TYPE_NAME = None
IS_ELF64 = None


def detect_elf64(bv):
    """Return True for ELF64, False for ELF32, or None if unknown."""
    if bv.read(0, 4) == b"\x7fELF":
        ei_class = bv.read(4, 1)[0]
        if ei_class == 1:
            return False
        if ei_class == 2:
            return True
        return None

    if bv.arch.address_size == 8:
        return True
    if bv.arch.address_size == 4:
        return False
    return None


def configure_elf_types(is_64bit):
    global Elf_Sym, Elf_Rela, ELF_RELA_TYPE_NAME, IS_ELF64

    IS_ELF64 = is_64bit
    if is_64bit:
        Elf_Sym = Elf64_Sym
        Elf_Rela = Elf64_Rela
        ELF_RELA_TYPE_NAME = "Elf64_Rela"
    else:
        Elf_Sym = Elf32_Sym
        Elf_Rela = Elf32_Rela
        ELF_RELA_TYPE_NAME = "Elf32_Rela"


def decode_r_info(r_info):
    if IS_ELF64:
        sym = r_info >> 32
        typ = r_info & 0xffffffff
    else:
        sym = r_info >> 8
        typ = r_info & 0xff
    return sym, typ


def get_sym_name(bv, dynsym, dynstr, sym_index):
    sym_addr = dynsym.start + sym_index * Elf_Sym.size
    st_name = int.from_bytes(bv.read(sym_addr, 4), "little")

    name_addr = dynstr.start + st_name
    s = bv.get_ascii_string_at(name_addr)
    return s.value if s else None


def resolve_elf_symbols(bv):
    is_64bit = detect_elf64(bv)
    if is_64bit is None:
        log_error("Could not determine ELF class (expected 32- or 64-bit)")
        return

    configure_elf_types(is_64bit)
    log_info(f"ELF{'64' if is_64bit else '32'} binary detected")

    rela = bv.sections.get(".rela.plt")
    dynsym = bv.sections.get(".dynsym")
    dynstr = bv.sections.get(".dynstr")

    if not dynsym or not dynstr:
        log_error("Missing .dynsym or .dynstr")
        return

    if rela:
        data = bv.read(rela.start, rela.length)
        count = len(data) // Elf_Rela.size
        t = bv.parse_type_string(f"{ELF_RELA_TYPE_NAME}[{count}]")
        bv.define_data_var(rela.start, t[0])

    for i in range(dynsym.length // Elf_Sym.size):
        sym_addr = dynsym.start + i * Elf_Sym.size
        name = get_sym_name(bv, dynsym, dynstr, i)
        if not name:
            continue

        bv.set_comment_at(sym_addr, name)
        bv.define_user_symbol(Symbol(SymbolType.ExternalSymbol, sym_addr, "dyn_" + name))


resolve_elf_symbols(bv)
