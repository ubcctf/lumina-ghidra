from ghidra.util import Msg
from ghidra.program.database.function import FunctionDB
from ghidra.program.database import ProgramDB
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl, LocalVariableImpl, VariableUtilities, VariableStorage
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.data import Undefined
from java.util import Arrays

import socket, itertools

from construct import *
from lumina_structs import *
from lumina_structs.metadata import *

from .sig.util import Sig, ARCH_MAPPING
from .type import construct_type, cc_mapping

#
# Push Functions
#

def extract_md(ctx: ProgramDB, func: FunctionDB, gen: Sig) -> dict:
    chunks = []

    #turns out func.getComment and getRepeatableComment are just plate comments and repeatable comments at the entry point address
    if func.getComment():
        chunks.append({
            'type': MetadataType.MD_FUNC_CMT,
            'data': {'text': func.getComment()}})
    
    if func.getRepeatableComment():
        chunks.append({
            'type': MetadataType.MD_FUNC_REPCMT,
            'data': {'text': func.getRepeatableComment()}})

    prog = FlatProgramAPI(ctx)

    func_start = func.getEntryPoint().getOffset()

    #EOL comments are always instruction comments
    eol = [{'offset': addr.getOffset() - func_start,
            'text': prog.getEOLComment(addr)} 
            for addr in ctx.getCodeManager().getCommentAddressIterator(CodeUnit.EOL_COMMENT, func.getBody(), True)]
    if eol:
        chunks.append({
            'type': MetadataType.MD_INSN_CMT,
            'data': eol})

    #repeatable comments are instruction comments, aside from the entry point one, which we need to check for that case
    rep = [{'offset': addr.getOffset() - func_start,
            'text': prog.getRepeatableComment(addr)} 
            for addr in ctx.getCodeManager().getCommentAddressIterator(CodeUnit.REPEATABLE_COMMENT, func.getBody(), True)
            if addr.getOffset() != func_start]
    if rep:
        chunks.append({
            'type': MetadataType.MD_INSN_REPCMT,
            'data': rep})


    #do both pre and post at the same time; pre and post comments will never be related to function comments so we are good
    extra = [{'offset': addr.getOffset() - func_start,
            'anterior': pre if pre else '',
            'posterior': post if post else ''} 
            for addr in ctx.getCodeManager().getCommentAddressIterator(func.getBody(), True)
            if any([(pre:=prog.getPreComment(addr)), (post:=prog.getPostComment(addr))])]  #either one of them exists then we can add; prevent short circuit evaluation
    if extra:
        chunks.append({
            'type': MetadataType.MD_EXTRA_CMT,
            'data': extra})

    #TODO frame info and tinfo
    #OPREPRS as a concept doesnt really exist in Ghidra either(??)
    #but might be helpful in defining data vars so parsing might be good

    is_non_auto_name = func.getSymbol() and func.getSymbol().getSource() == SourceType.USER_DEFINED
    if chunks or is_non_auto_name: #only compute signature and returns something if has data
        data = gen.calc_func_metadata(func)
        if not data:
            return None
        
        sig, block, mask = data
        return {
            "metadata": {
                "func_name": func.getName(),  #func name is automatically whatever it should be
                "func_size": len(block),
                "serialized_data": {
                    "chunks": chunks}},
            "signature": {
                "version": 1, 
                "signature": sig}}
    else:
        return None



def craft_push_md(ctx: ProgramDB, funcs: list[FunctionDB], tool: PluginTool = None) -> dict:
    arch = ARCH_MAPPING[ctx.getLanguage().getProcessor().toString()](ctx)  #again, Ghidra only allows one arch at a time

    progress = "[Lumina] Extracting function metadata ({count}/" + str(len(funcs)) + " functions)"
    push, eas = [], []
    for i, f in enumerate(funcs):
        md = extract_md(ctx, f, arch)
        if md: #only apply if extracted useful data
            push.append(md)
            eas.append(f.getEntryPoint().getOffset())
        if tool:
            tool.setStatusInfo(progress.format(count=i))

    return {
        "type": PushMdOpt.PUSH_OVERRIDE_IF_BETTER,  #protocol 2 default
        "idb_filepath": ctx.getDomainFile().getProjectLocator().getProjectDir().getPath(), 
        "input_filepath": ctx.getExecutablePath(), 
        "input_md5": bytes.fromhex(ctx.getExecutableMD5()),   #Ghidra actually has a function for this so we dont need to reread the file ourselves
        "hostname": socket.gethostname(),
        "funcInfos": push,
        "funcEas": eas}  #seems like ida is offset by one???


#
# Pull Functions
#


#again, ghidra support only one arch at a time so no more lists
def craft_pull_md(ctx: ProgramDB, fs: list[FunctionDB], tool: PluginTool = None) -> dict:
    arch = ARCH_MAPPING[ctx.getLanguage().getProcessor().toString()](ctx)

    sigs = []
    i = 0
    progress = "[Lumina] Calculating function signatures ({count}/" + str(len(fs)) + " functions)"
    for func in fs:
        if tool:
            tool.setStatusInfo(progress.format(count=i))

        sig = arch.calc_func_metadata(func)
        if sig:
            sigs.append({'signature':sig[0]})

        i+=1

    return {'flags': 1,  #protocol 2 default
        'types':[],
        'funcInfos':sigs}


#we need tool for passing DataTypeManagerService to construct_cmplx unfortunately 
def apply_md(ctx: ProgramDB, func: FunctionDB, tool: PluginTool, info: Container):
    #we don't really care about popularity atm, but it might be useful server side for sorting

    #IDA (at least on 7.5) hardcoded no-override flag into apply_metadata, so tinfo and frame desc effectively never gets applied even if existing data is entirely auto-generated
    #we won't follow that - manually clearing the data on every lumina pull is very annoying and there is undo anyway
    #instead we will default to resetting metadata to what lumina provides on conflict
    prog = FlatProgramAPI(ctx)

    prog.start() #start a transaction

    func.setName(info.metadata.func_name, SourceType.IMPORTED)
    #func size should be the same to be able to get the same signature, so no need to set
    for md in info.metadata.serialized_data.chunks:
        if md.type in [MetadataType.MD_INSN_CMT, MetadataType.MD_INSN_REPCMT]:
            for c in md.data:
                addr = func.getEntryPoint().add(c.offset)
                setComment = prog.setEOLComment if md.type == MetadataType.MD_INSN_CMT else prog.setRepeatableComment
                setComment(addr, c.text)
        elif md.type in [MetadataType.MD_FUNC_CMT, MetadataType.MD_FUNC_REPCMT]:
            #ghidra actually has repeatable comments, treat them separately
            setComment = func.setComment if md.type == MetadataType.MD_FUNC_CMT else func.setRepeatableComment
            setComment(md.data.text)
        elif md.type == MetadataType.MD_EXTRA_CMT:
            #Ghidra actually has anterior and posterior comments, treat them separately
            for c in md.data:
                addr = func.getEntryPoint().add(c.offset)
                if c.anterior:
                    prog.setPreComment(addr, c.anterior)
                if c.posterior:
                    prog.setPostComment(addr, c.posterior)
        elif md.type == MetadataType.MD_TYPE_INFO:
            #cannot reuse FunctionDefinitionDataType unfortunately since we have to directly set in the current func
            #md.data.tinfo should always be BT_FUNC
            params = []
            for param in md.data.tinfo.data.params:
                name = md.data.names.pop(0) if md.data.names else ""
                params.append(ParameterImpl(name, construct_type(tool, param.type, md.data.names), ctx))
            params = Arrays.asList(params)
                
            func.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.IMPORTED)
            func.setReturnType(construct_type(tool, md.data.tinfo.data.rettype, md.data.names), SourceType.IMPORTED)
            if md.data.tinfo.data.cc.convention in cc_mapping:
                cc = cc_mapping[md.data.tinfo.data.cc.convention].getDeclarationName()
                func.setCallingConvention(cc if cc != '__cdecl' else '__stdcall')  #somehow cdecl doesnt exist (at least on ghidra 10.1.4) and is mapped to __stdcall according to the DWARF parser

            #ghidra doesnt have near/far calls(?)
            #TODO custom calling conventions since ghidra actually supports reordering with argloc (VariableStorage)
            #i dont think spoiled registers can be defined though
        elif md.type == MetadataType.MD_FRAME_DESC:
            #ghidra doesnt have the variable definition section for comments storage, so discard for now; also oprepr as a concept doesnt exist in ghidra either
            for var in md.data.vars:
                #sometimes type == None if its default so just treat it as undefined type of nbytes
                print(var.name, var.type.tinfo if var.type else None)
                t = construct_type(tool, var.type.tinfo, var.type.names, var.nbytes) if var.type else Undefined.getUndefinedDataType(var.nbytes)
                name = var.name if var.name else f'lumina_{hex(var.off)}'

                #TODO check if this still matches in architectures with stack growing up (also are we sure frregs is for this purpose)
                #ghidra also uses rbp instead of rsp (offset goes down instead of up)
                v = LocalVariableImpl(name, t, -(md.data.frsize - var.off + md.data.frregs), ctx)

                #TODO argloc
                VariableUtilities.checkVariableConflict(func, v, v.getVariableStorage(), True)
                func.addLocalVariable(v, SourceType.IMPORTED)
        else:
            Msg.debug("Lumina", 'Unimplemented metadata type ' + str(md.type) + ', skipping for now...')

    prog.end(True) #end the transaction
