import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

DolHeaderSize = 0x100
DolFormatName = "Nintendo GC/Wii DOL"
MaxCodeSection = 7
MaxDataSection = 11

class DolHeader(BigEndianStructure):
    _fields_ = [
            ("text_offsets", c_uint * MaxCodeSection),
            ("data_offsets", c_uint * MaxDataSection),
            ("text_addresses", c_uint * MaxCodeSection),
            ("data_addresses", c_uint * MaxDataSection),
            ("text_sizes", c_uint * MaxCodeSection),
            ("data_sizes", c_uint * MaxDataSection),
            ("bss_address", c_uint),
            ("bss_size", c_uint),
            ("entry_point", c_uint),
            ]

def get_dol_header(li):
    li.seek(0)
    header = DolHeader()
    string = li.read(DolHeaderSize)
    memmove(addressof(header), string, DolHeaderSize)
    return header

def section_sanity_check(offset, addr, size, file_len):
    if offset != 0 and offset < DolHeaderSize:
        return False
    if (offset + size) > file_len:
        return False
    if addr and (addr & 0x80000000 == 0):
        return False

    return True

def accept_file(li, n):

    valid_ep = False

    if n:
        return False

    li.seek(0, os.SEEK_END)
    file_len = li.tell()
    if file_len < DolHeaderSize:
        return False

    header = get_dol_header(li)

    for i in xrange(MaxCodeSection):
        if not section_sanity_check(header.text_offsets[i],
                header.text_addresses[i],
                header.text_sizes[i],
                file_len):
            return False


        section_limit = header.text_addresses[i] + header.text_sizes[i]
        if (header.entry_point >= header.text_addresses[i] and
            header.entry_point < section_limit):
                valid_ep = True

    if not valid_ep:
        return False

    for i in xrange(MaxDataSection):
        if not section_sanity_check(header.data_offsets[i],
                header.data_addresses[i],
                header.data_sizes[i],
                file_len):
            return False

    if not section_sanity_check(0, header.bss_address, header.bss_size, file_len):
        return False


    return DolFormatName

def load_file(li, neflags, fmt):
	if fmt != DolFormatName:
		Warning("Unknown format name: '{0}'".format(fmt))

        set_processor_type("PPC", SETPROC_ALL|SETPROC_FATAL)
        set_compiler_id(COMP_GNU)

        header = get_dol_header(li)

        cvar.inf.beginEA = cvar.inf.startIP = header.entry_point
        set_selector(1, 0);

        flags = ADDSEG_NOTRUNC|ADDSEG_OR_DIE

        for i in xrange(MaxCodeSection):

            if header.text_sizes[i] == 0:
                continue

            addr = header.text_addresses[i]
            size = header.text_sizes[i]
            off = header.text_offsets[i]

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "Code{0}".format(i))
            SetSegmentType(addr, SEG_CODE)
            li.file2base(off, addr, addr + size, 0)

        for i in xrange(MaxDataSection):

            if header.data_sizes[i] == 0:
                continue

            addr = header.data_addresses[i]
            size = header.data_sizes[i]
            off = header.data_offsets[i]

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "Data{0}".format(i))
            SetSegmentType(addr, SEG_DATA)
            li.file2base(off, addr, addr + size, 0)

        if header.bss_address:
            addr = header.bss_address
            size = header.bss_size

            AddSegEx(addr, addr + size, 0, 1, saRelPara, scPub, flags)
            RenameSeg(addr, "BSS")
            SetSegmentType(addr, SEG_BSS)

        return True



