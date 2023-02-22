from lumina_structs.tinfo import *
from construct import Container
from ghidra.program.model.data import (DataType, VoidDataType,
    CharDataType, SignedByteDataType, ByteDataType,
    SignedWordDataType, WordDataType, SignedDWordDataType, DWordDataType,
    SignedQWordDataType, QWordDataType, Integer16DataType, UnsignedInteger16DataType,
    IntegerDataType, UnsignedIntegerDataType, BooleanDataType,
    FloatDataType, DoubleDataType, LongDoubleDataType, Float2DataType,
    PointerDataType, ArrayDataType, FunctionDefinitionDataType,
    TypedefDataType, Undefined, BitFieldDataType)
from ghidra.program.model.data import ParameterDefinitionImpl, GenericCallingConvention
from ghidra.framework.plugintool import PluginTool
from ghidra.app.services import DataTypeManagerService
from java.util import ArrayList
from typing import List, Optional

#
# handles mapping from generic lumina tinfo definitions to ghidra-specific data
#

def construct_ptr(tinfo: Container, tool: PluginTool, names: Optional[List[str]], *_):
    #ghidra seem to only have the basics in ptr types (no const/volatile, no closures, no near/far etc)
    if tinfo.data.ptrsize:
        return PointerDataType(construct_type(tool, tinfo.data.type, names), tinfo.data.ptrsize)
    else:
        #assuming dynamic pointer size means itll eventually be the right one
        return PointerDataType(construct_type(tool, tinfo.data.type, names))

def construct_arr(tinfo: Container, tool: PluginTool, names: Optional[List[str]], *_):
    #ghidra have no "base of array" concepts, assume zero always
    t = construct_type(tool, tinfo.data.type, names)
    return ArrayDataType(t, tinfo.data.num_elems, t.getLength())


cc_mapping = {
    CallingConvention.CM_CC_CDECL: GenericCallingConvention.cdecl,
    CallingConvention.CM_CC_ELLIPSIS: GenericCallingConvention.cdecl,
    CallingConvention.CM_CC_STDCALL: GenericCallingConvention.stdcall,
    CallingConvention.CM_CC_PASCAL: GenericCallingConvention.stdcall,    #but reversed order of args
    CallingConvention.CM_CC_FASTCALL: GenericCallingConvention.fastcall,
    CallingConvention.CM_CC_THISCALL: GenericCallingConvention.thiscall,
}

def construct_func(tinfo: Container, tool: PluginTool, names: Optional[List[str]], *_):
    #again seems like the data types are pretty basic, aka no arglocs, near/far, spoiled regs etcetc
    funcdef = FunctionDefinitionDataType("lumina_function")  #temp name for generating

    funcdef.setReturnType(construct_type(tool, tinfo.data.rettype, names))
    funcdef.setArguments([ParameterDefinitionImpl(names.pop(0) if names else "", construct_type(tool, param.type, names), None) for param in tinfo.data.params])
    if tinfo.data.cc.convention in cc_mapping:
        funcdef.setGenericCallingConvention(cc_mapping[tinfo.data.cc.convention])

    funcdef.setName(funcdef.getPrototypeString())

    return funcdef

def construct_cmplx(tinfo: Container, tool: PluginTool, names: Optional[List[str]], nbytes: int):
    #lumina only pushes typedef, so not much we can do if it doesnt already exist in type libraries
    if tinfo.typedef.flags == ComplexFlags.BTMT_TYPEDEF:   #just to be sure we are dealing with typedefs before we search the name up
        #we either just use the state in the global scope to get every type library or we have to pass it through a whole chain of things which is not ideal
        for lib in tool.getService(DataTypeManagerService).getDataTypeManagers():    
            l = ArrayList()
            lib.findDataTypes(tinfo.data.name, l)
            if l:
                #if nbytes is defined and the type we got is very likely defined by lumina (typedef -> undefined), trust that
                if hasattr(l[0], 'getBaseDataType') and Undefined.isUndefined(l[0].getBaseDataType()) and nbytes:
                    l[0].replaceWith(TypedefDataType(tinfo.data.name, Undefined.getUndefinedDataType(nbytes)))
                return l[0]
        return TypedefDataType(tinfo.data.name, Undefined.getUndefinedDataType(nbytes))
    
    #TODO properly parse the complex types once ive figured out ways to force lumina to push full struct info (or extend it to do that)
    #this should basically never be reached before then
    return Undefined.getUndefinedDataType(nbytes)

bitfield_mapping = {
    BitFieldFlags.BTMT_BFLDI8: (ByteDataType, SignedByteDataType),
    BitFieldFlags.BTMT_BFLDI16: (WordDataType, SignedWordDataType),
    BitFieldFlags.BTMT_BFLDI32: (DWordDataType, SignedDWordDataType),
    BitFieldFlags.BTMT_BFLDI64: (QWordDataType, SignedQWordDataType),
}

def construct_bitfield(tinfo: Container, *_):  #ive never seen this in use - see lumina_structs.tinfo for more info
    #BitFieldDataType is technically an internal class, but we should be fine since BT_BITFIELD is also only used in structs in IDA
    return BitFieldDataType(bitfield_mapping[tinfo.typedef.flags][int(not tinfo.data.unsigned)], tinfo.data.bitsize)



float_mapping = {
    FloatFlags.BTMT_FLOAT: FloatDataType.dataType,
    FloatFlags.BTMT_DOUBLE: DoubleDataType.dataType,
    FloatFlags.BTMT_LNGDBL: LongDoubleDataType.dataType,
    FloatFlags.BTMT_SPECFLT: Float2DataType.dataType, #depends on use_tbyte() in IDA otherwise 2 - likely not used for lumina
}

basetype_mapping = {
    BaseTypes.BT_VOID: lambda *_: VoidDataType.dataType,
    BaseTypes.BT_INT8: lambda tinfo, *_: CharDataType.dataType if tinfo.typedef.flags == IntFlags.BTMT_CHAR else (SignedByteDataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else ByteDataType.dataType),  #default to signed unless unsigned is specified
    BaseTypes.BT_INT16: lambda tinfo, *_: SignedWordDataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else WordDataType.dataType,
    BaseTypes.BT_INT32: lambda tinfo, *_: SignedDWordDataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else DWordDataType.dataType,
    BaseTypes.BT_INT64: lambda tinfo, *_: SignedQWordDataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else QWordDataType.dataType,
    BaseTypes.BT_INT128: lambda tinfo, *_: Integer16DataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else UnsignedInteger16DataType.dataType,
    BaseTypes.BT_INT: lambda tinfo, *_: IntegerDataType.dataType if not tinfo.typedef.flags == IntFlags.BTMT_USIGNED else UnsignedIntegerDataType.dataType,
    BaseTypes.BT_BOOL: lambda *_: BooleanDataType.dataType,
    BaseTypes.BT_FLOAT: lambda tinfo, *_: float_mapping[tinfo.typedef.flags],
    #complex types
    BaseTypes.BT_PTR: construct_ptr,
    BaseTypes.BT_ARRAY: construct_arr,
    BaseTypes.BT_FUNC: construct_func,
    BaseTypes.BT_COMPLEX: construct_cmplx,
    BaseTypes.BT_BITFIELD: construct_bitfield,
}


def construct_type(tool: PluginTool, tinfo: Container, names: Optional[List[str]] = None, nbytes: int = 0) -> DataType:
    #trust nbytes more than type info coz sometimes its missing width (especially typedefs)
    #though thats only on the first layer - we reuse types from libraries which ends up having the wrong nbytes size if a typedef is indirectly referred, so dont propagate
    return basetype_mapping[tinfo.typedef.basetype](tinfo, tool, names, nbytes)
