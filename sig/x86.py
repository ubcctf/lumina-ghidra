from ghidra.program.database.function import FunctionDB
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SymbolType
import jep

from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_FS, X86_REG_GS, X86_REG_RIP, X86_OP_MEM, X86_OP_IMM

import io, ctypes

from .util import Sig


class X86(Sig):

    def valid_loc(self, offset: Address, f: FunctionDB):
        #include all data variables that has a code ref 
        #also include if is pointing to start of instruction, but never mask same function jumps
        #sometimes there might be multiple functions at the same address even on the same architecture it seems like - we check all of them to see if any is the same function then reject
        #ghidra cant have multiple functions at the same location
        #if a data var exists (undefined or not) at offset there has to be a reference in ghidra
        return offset and (((o:=self.prog.getFunctionContaining(offset)) and o.getEntryPoint() != f.getEntryPoint() and self.prog.getInstructionAt(offset)) or self.prog.getDataContaining(offset) or self.prog.getUndefinedDataAt(offset))
        #jep jarrays are correctly falsey


    def calcrel(self, d: CsInsn, f: FunctionDB):
        mask = bytes(d.size)

        #<opcode, disp_offset, imm_offset> - offsets are optional and can not exist
        #afaik x86 imm is always at the end

        if d.disp_offset: #consider references - any fs address, any relative memory accesses that's valid in program scope (see valid_loc def)
            m = b'\xFF' if any(op.type == X86_OP_MEM and (op.reg in [X86_REG_FS, X86_REG_GS] or (op.value.mem.base == X86_REG_RIP and self.valid_loc(self.prog.getAddressFactory().getAddress(hex(op.value.mem.disp + d.address + d.size)), f))) for op in d.operands) else b'\0'
            size = (d.imm_offset - d.disp_offset if d.imm_offset else d.size - d.disp_offset)
            mask = mask[:d.disp_offset] + m*size + mask[d.disp_offset+size:]

        #imm always later than disp
        if d.imm_offset: #references in imm just points directly to addresses
            m = b'\xFF' if any(op.type == X86_OP_IMM and self.valid_loc(self.prog.getAddressFactory().getAddress(hex(op.imm)), f) for op in d.operands) else b'\0'
            size = d.size - d.imm_offset
            mask = mask[:d.imm_offset] + m*size + mask[d.imm_offset+size:]

        return mask

    def calc_func_metadata(self, func: FunctionDB) -> tuple[str, bytes, bytes]:

        if func.isThunk() and func.getThunkedFunction(False).isExternal():   #special functions, ignore
            return

        ranges = func.getBody()

        #dont check the portions of the function above func.start (aka no min([r.start for r in ranges])); seems like IDA doesnt care either and this speeds things up by a ton in binaries with exception handlers
        func_start = func.getEntryPoint().getOffset()
        func_end = ranges.getMaxAddress().getOffset()  #get max of the entire address space

        cap = Cs(CS_ARCH_X86, CS_MODE_64)  #seems like 64bit mode can still disassemble 32 bit completely fine
        cap.detail = True

        #take the entire block of data including alignment into account (use size if disassembly is not available)
        #pass by reference workaround - we cant directly use b'' coz jep will just copy the array into java and then discard the changed result
        jblock = jep.jarray(func_end - func_start + 1, jep.JBYTE_ID)  #func_end inclusive
        self.mem.getBytes(func.getEntryPoint(), jblock)
        block = bytes([ctypes.c_ubyte(b).value for b in jblock]) #java bytes are signed

        #linearly disassemble the entire block of bytes that the function encompasses (IDA does that instead of checking whether the bytes are accessible to the function or not)
        dis = cap.disasm(block, func_start) 

        maskblock = io.BytesIO(bytes(len(block)))
        block = io.BytesIO(block)
        #if its in the valid proc address space then it counts as volatile
        for d in dis:
            maskblock.seek(d.address - func_start)
            block.seek(d.address - func_start)

            mask = (self.calcrel(d, func))
            data = bytes([b if m != 0xFF else 0 for m, b in zip(mask, block.read(len(mask)))])

            maskblock.write(mask)
            
            block.seek(d.address - func_start)
            block.write(data)
        block = block.getvalue()
        maskblock = maskblock.getvalue()

        #compute MD5
        import hashlib

        hash = hashlib.md5(block + maskblock).digest()
        return hash, block, maskblock