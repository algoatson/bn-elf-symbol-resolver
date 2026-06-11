from binaryninja import *
import struct

Elf64_Rela = struct.Struct("<QQq") # 24 bytes
Elf64_Sym  = struct.Struct("<IBBHQQ")

def decode_r_info(r_info):
    sym = r_info >> 32         # index into .dynsym
    typ = r_info & 0xffffffff  # relocation type
    return sym, typ

def get_sym_name(sym_index):
    sym_addr = dynsym.start + sym_index * 24
    st_name = int.from_bytes(bv.read(sym_addr, 4), "little")

    name_addr =  dynstr.start + st_name
    return str(bv.get_ascii_string_at(name_addr))

rela = bv.sections.get('.rela.plt')
dynsym = bv.sections.get('.dynsym')
dynstr = bv.sections.get('.dynstr')

data = bv.read(rela.start, rela.length)

count = len(data) // Elf64_Rela.size
t = bv.parse_type_string(f"Elf64_Rela[{count}]")

bv.define_data_var(rela.start, t[0])

for i in range(dynsym.length // Elf64_Sym.size):
    sym_addr = dynsym.start + i * Elf64_Sym.size
    name = get_sym_name(i)
    if not name:
        continue

    st_name_addr = sym_addr
    bv.set_comment_at(st_name_addr, name)
