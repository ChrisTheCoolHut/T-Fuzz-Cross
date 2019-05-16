import r2pipe
from intervaltree import Interval, IntervalTree
import argparse
import capstone
import keystone
import archinfo
import re
import array
from contextlib import contextmanager

class Radare2(object):

    def __init__(self, program, flags=None):
        self.program = program

        # if flags == None:
        #     flags = ['-w']

        # if '-w' not in flags:
        #     flags.append('-w')

        if flags != None and isinstance(flags, list):
            self.r2 = r2pipe.open(self.program, flags=flags)
        else:
            self.r2 = r2pipe.open(self.program)
        # self.r2.cmd("aa")

        i_json = self.r2.cmdj('ij')
        self.os = i_json['bin']['os']
        self.arch = i_json['bin']['arch']
        self.bits  = i_json['bin']['bits']
        self.pic  = i_json['bin']['pic']
        self.endian = i_json['bin']['endian']


        if self.arch == 'x86':
            if self.bits == 64:
                self.archinfo = archinfo.ArchAMD64
            else:
                self.archinfo = archinfo.ArchX86
        elif self.arch == 'mips':
            if self.bits == 32:
                self.archinfo = archinfo.ArchMIPS32
            elif self.bits == 64:
                self.archinfo = archinfo.ArchMIPS64
        elif self.arch == 'arm':
            self.archinfo = archinfo.ArchARM
        elif self.arch == 'ppc':
            if self.bits == 32:
                self.archinfo = archinfo.ArchPPC32
            elif self.bits == 64:
                self.archinfo = archinfo.ArchPPC64
        elif self.arch == 'aarch64':
            self.archinfo = archinfo.AArch64
        else:
            self.archinfo = None

        if self.archinfo is not None:
            if self.endian == "little":
                self.archinfo.memory_endess = archinfo.Endness.LE
            else:
                self.archinfo.memory_endess = archinfo.Endness.BE

        if self.archinfo != None:
            self.md = capstone.Cs(self.archinfo.cs_arch, self.archinfo.cs_mode)
            self.cs = keystone.Ks(self.archinfo.ks_arch, self.archinfo.ks_mode)
        else:
            self.md = None

    def __getitem__(self, key):
        self.r2.cmd('s ' + hex(key))
        ret = self.r2.cmd('p8 1')
        try:
            ret = int(ret, base=16)
        except ValueError:
            ret = None

        return ret

    def __setitem__(self, key, val):
        val = val & 0xFF
        val = "{0:0x}".format(val)
        self.r2.cmd('s ' + hex(key))
        self.r2.cmd('wx ' + val)

    def get_bytes_n(self, addr, n):
        '''
        This function returns an array of `n` bytes
        '''
        self.r2.cmd('s ' + hex(addr))

        return self.r2.cmdj('pcj ' + str(n))

    def get_cjump_addr(self, blk_addr):
        code_byte_array = self.get_bytes_n(blk_addr, 1024)
        code_char_array = [chr(b) for b in code_byte_array]
        code_str = ''.join(code_char_array)
        code_str  = str.encode(code_str)
        gen = self.md.disasm(code_str, blk_addr)

        if self.arch == 'x86':
            for i in gen:
                if i.mnemonic.startswith('j') and i.mnemonic != 'jmp':
                    # print("Found a jump instruction at %s(%d): %s"%(hex(i.address), i.size,
                    #                                                i.mnemonic + ' ' + i.op_str))
                    return i.address
        if self.arch == 'mips' or  self.arch == 'arm':
            for i in gen:
                if i.mnemonic.startswith('b') and i.mnemonic not in ['b', 'bx', 'blx']:
                    #print("Found a branch instruction at %s(%d): %s"%(hex(i.address), i.size,
                    #                                              i.mnemonic + ' ' + i.op_str))
                    return i.address


        print("Conditional jump instruction not found")
        return 0

    def get_branch_pairs(self):
        if self.md == None:
            raise NotImplementedError

        # http://unixwiz.net/techtips/x86-jumps.html
        if self.arch == "x86":
            branch_pairs ={
                'jo':'jno',
                'js': 'jns',
                'je': 'jne',
                'jz': 'jnz',
                'jb': 'jnb',
                'jae': 'jnae',
                'jc': 'jnc',
                'ja': 'jna',
                'jbe': 'jnbe',
                'jl': 'jnl',
                'jge': 'jnge',
                'jg': 'jng',
                'jle': 'jnle',
                'jp': 'jnp',
                'jpe': 'jpo',
                'jcxz': 'jecxz'
            }

        elif self.arch == "mips":
            branch_pairs ={
                    'bczt' : 'bczf',
                    'beq' : 'bne',
                    'beqz' : 'bnez',
                    'bge' : 'blt',
                    'bgeu' : 'bltu',
                    'bgt' : 'ble',
                    'bgtu' : 'bleu',
                    'bgtz' : 'blez',  
                    'bgez' : 'bltz',
                    'bgezal' : 'bltzal'
                    }

        elif self.arch == "arm":
            branch_pairs  = {}
            for B in ['b', 'bx', 'blx']:

                sub_pairing = {
                        B + 'eq' : B + 'ne',
                        B + 'hs' : B + 'lo',
                        B + 'mi' : B + 'pl',
                        B + 'vs' : B + 'vc',
                        B + 'hi' : B + 'ls',
                        B + 'ge' : B + 'lt',
                        B + 'gt' : B + 'le'
                        }

                branch_pairs = {**branch_pairs, **sub_pairing}

        else:
            raise NotImplementedError

        # add the original map
        branch_map = branch_pairs.copy()

        # add the reverse map
        for ji in branch_pairs.keys():
            branch_map[branch_pairs[ji]] = ji

        return branch_map


    def negate_cjmp(self, cjump_inst_addr):

        branch_map =  self.get_branch_pairs()

        code_byte_array = self.get_bytes_n(cjump_inst_addr, 1024)
        code_char_array = [chr(b) for b in code_byte_array]
        code_str = ''.join(code_char_array)
        code_str = str.encode(code_str)
        gen = self.md.disasm(code_str, cjump_inst_addr)

        try:
            gen = self.md.disasm(code_str, cjump_inst_addr)
            i = next(gen)
        except StopIteration as e:
            return

        # we use this heuristic to determine it is a jump instruction
        if i.mnemonic not in branch_map:
            #print("It is not a conditional jump instruction at @%s:%s" %
            #      (hex(cjump_inst_addr), i.mnemonic + ' ' + i.op_str))
            return

        self.r2.cmd('s ' + str(i.address))

        # then negate the conditional jump instruction
        if self.arch == 'x86':
            self.r2.cmd('wa ' + branch_map[i.mnemonic] + ' ' + i.op_str)

        if self.arch == 'mips' or self.arch == 'arm':

            print("Was {} {}".format(i.mnemonic,  i.op_str))
            ins_bytes_array = self.r2.cmdj('pxj 4')
            ins_bytes = array.array('B', ins_bytes_array).tostring()

            no_offset_ins = [x for x in self.md.disasm(ins_bytes, 0)][0]
            inverted_ins = str.encode(branch_map[no_offset_ins.mnemonic] + ' ' + no_offset_ins.op_str)

            print("Now {}".format(inverted_ins))
            encoding, count = self.cs.asm(inverted_ins, 0)

            if self.bits == 32:
                encoding = encoding[:4]

            inv_ins_bytes = array.array('B', ins_bytes).tostring()
            bytes_as_hex = inv_ins_bytes.hex()

            self.r2.cmd('wx ' + bytes_as_hex)

        return i.address

    def close(self):
        try:
            self.r2.quit()
        except:
            pass

    def __del__(self):
        self.close()


@contextmanager
def closing_r2(r2):
    try:
        yield r2
    finally:
        r2.close()

