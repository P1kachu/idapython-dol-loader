import os
from idc import *
from idaapi import *
from struct import unpack as up
from ctypes import *

DolHeaderSize = 0x100
DolFormatName = "Nintendo GC/WII DOL"

class DolHeader(BigEndianStructure):
    _fields_ = [
            ("text_offsets", c_uint * 7),
            ("data_offsets", c_uint * 11),
            ("text_addresses", c_uint * 7),
            ("data_addresses", c_uint * 11),
            ("text_sizes", c_uint * 7),
            ("data_sizes", c_uint * 11),
            ("bss_address", c_uint),
            ("bss_size", c_uint),
            ("entry_point", c_uint),
            ]

    def __str__(self):
        ret = "Text sections:\nOffset   | Address  |  Size\n"
        for x in xrange(7):
            if self.text_sizes[x] == 0:
                continue

            ret += "{:08x} | {:08x} | {:08x}\n".format(
                    self.text_offsets[x],
                    self.text_addresses[x],
                    self.text_sizes[x])

        ret += "\nData sections:\nOffset   | Address  |  Size\n"
        for x in xrange(7):
            if self.data_sizes[x] == 0:
                continue

            ret += "{:08x} | {:08x} | {:08x}\n".format(
                    self.data_offsets[x],
                    self.data_addresses[x],
                    self.data_sizes[x])

        ret += "\nBSS at {:08x} of size {:08x}".format(self.bss_address, self.bss_size)
        ret += "\nEntry point at {:08x}".format(self.entry_point)


        return ret

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

    return 1



def accept_file(li, n):

    valid_ep = False

    if n:
        return False

    li.seek(0, os.SEEK_END)
    file_len = li.tell()
    if file_len < DolHeaderSize:
        return False
    li.seek(0)

    header = get_dol_header(li)

    for i in xrange(7):
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

    for i in xrange(11):
        if not section_sanity_check(header.data_offsets[i],
                header.data_addresses[i],
                header.data_sizes[i],
                file_len):
            return False

    if not section_sanity_check(0, header.bss_address, header.bss_size, file_len):
        return False


    return DolFormatName

def load_file(li, neflags, format):
	if format != DolFormatName:
		Warning("Unknown format name: '%s'" % format)
    	        return False

        set_processor_type("PPC", SETPROC_ALL|SETPROC_FATAL)
        set_compiler_id(COMP_GNU)

        header = get_dol_header(li)

        cvar.inf.beginEA = cvar.inf.startIP = header.entry_point
        set_selector(1, 0);

        for i in xrange(7):

            if header.text_sizes[i] == 0:
                continue

            addr = header.text_addresses[i]
            size = header.text_sizes[i]
            off = header.text_offsets[i]

            AddSeg(addr, addr + size, 0, 1, saRelPara, scPub)

            RenameSeg(addr, "Code{0}".format(i))
            SetSegmentType(addr, SEG_CODE)
            li.file2base(off, addr, size, 0)

        for i in xrange(11):

            if header.data_sizes[i] == 0:
                continue

            addr = header.data_addresses[i]
            size = header.data_sizes[i]
            off = header.data_offsets[i]

            AddSeg(addr, addr + size, 0, 1, saRelPara, scPub)

            RenameSeg(addr, "Data{0}".format(i))
            SetSegmentType(addr, SEG_DATA)
            li.file2base(off, addr, size, 0)

        if header.bss_address:
            addr = header.bss_address
            size = header.bss_size
            AddSeg(addr, addr + size, 0, 1, saRelPara, scPub)
            RenameSeg(addr, "BSS")
            SetSegmentType(addr, SEG_BSS)

        return True



