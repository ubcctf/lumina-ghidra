import frida

from ghidra.program.flatapi import FlatProgramAPI

from capstone import *

from sig.util import ARCH_MAPPING

import time

import os, subprocess

cs_mapping = {'x86': CS_ARCH_X86, 'x86_64': CS_ARCH_X86}

IDA_PATH = os.path.realpath(os.environ['IDADIR']) + os.path.sep


def check_against_ida(binary: str, verbosity: int, arch: str):
    #it's a hassle to automatically get ida offsets from ghidra so manual input it is for now
    metadata, update, final = input(), input(), input()

    cwd = input()  #manually enter the path to ida-calc-all-metadata coz __file__ doesnt exist

    #fetch the expected function signatures first

    #we rely on widget loading in ida-calc-all-metadata.py since we cant trigger calc_func_metadata other than running lumina which is why we need to run idat
    #with some tricks we can actually get idat to run headless and have widgets loaded like what we expect with gui mode
    #-c removes the old database so it doesnt affect operations between runs
    p = subprocess.Popen(IDA_PATH + 'idat64.exe -c -A -S' + cwd + 'ida-calc-all-metadata.py ' + binary, stdout=subprocess.PIPE)

    session = frida.attach(p.pid)

    script = session.create_script("""
    const baseAddr = Module.findBaseAddress('ida64.dll');"""
f"\n    const metadata  = resolveAddress('{metadata}');\n"
f"\n    const MD5Update = resolveAddress('{update}');\n"
f"\n    const MD5Final  = resolveAddress('{final}');\n"
    """
    var bytes = '';
    var funcptr = null;

    function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
    }

    Interceptor.attach(metadata, {
        onEnter(args) {
            funcptr = args[2].readU64();   //first param of func_t is start_ea, as shown in how calc_func_metadata uses get_ea_name
            bytes = '';  //prime bytes for writing
        },
    });

    Interceptor.attach(MD5Update, {
        onEnter(args) {
            bytes += ' ' + buf2hex(args[1].readByteArray(args[2].toInt32()));
        },
    });

    Interceptor.attach(MD5Final, {
        onEnter(args) {
            this.hashAddr = args[0];
            this.objAddr = args[1];
        },
        onLeave(retval) {
            if(funcptr !== null) {  //lumina functions always only have 2 as count; also ensure calc_func_metadata runs
                const hash = this.hashAddr.readByteArray(16);
                send(funcptr.toString(16) + ' ' + buf2hex(hash) + bytes);

                //reset
                funcptr = null;
            }
        },
    });

    function resolveAddress(addr) {
        const idaBase = ptr('0x10000000');
        const offset = ptr(addr).sub(idaBase);
        const result = baseAddr.add(offset);
        return result;
    }

    """)

    expected = []

    script.on('message', lambda msg, _: expected.append((int((pl:=msg['payload'].split(' '))[0], 16), pl[1], pl[2], pl[3])))
    script.load()
    

    #ghidraa already loaded currentProgram for us
    start = time.time()  #ignore open_view overhead in our timing
    
    gen = ARCH_MAPPING[arch](currentProgram)
    actual = {}
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if calcrel:=gen.calc_func_metadata(f):
            actual[f.getEntryPoint().getOffset()] = calcrel

    end = time.time()

    p.communicate()

    if not len(expected):
        print('Failed to obtain results from IDA, aborting...')
        return

    #check results

    missing = 0

    for addr, hash, buf, mask in list(expected):
        if addr not in actual:
            if verbosity > 0:
                print('Function missing from ghidra: ' + hex(addr))
            expected.remove((addr, hash, buf, mask))
            missing+=1

    if verbosity > 0:
        print()

    miss = 0
    cap = Cs(cs_mapping[arch], CS_MODE_64)
    for addr, hash, buf, mask in expected:  #we dont really care about ghidra exclusive functions i guess
        if actual[addr][0].hex() != hash:
            if verbosity > 0:
                print('\nFunction', hex(addr), 'mismatch:')
                print('Expected:', hash)
                print('Actual:', actual[addr][0].hex())

            if verbosity > 1:
                #print('\n' + actual[addr][1].hex() + '\n' + actual[addr][2].hex() + '\n' + buf + '\n\n')

                us = {d.address:str(d) for d in cap.disasm(actual[addr][1], addr)}
                ida = {d.address:str(d) for d in cap.disasm(bytes.fromhex(buf), addr)}

                #only compare the str form of the disassembly since the disasm objects themselves are different
                diff = set(ida.values()) ^ set(us.values())

                differing, excl_us, excl_ida = [], [], []
                for d in diff:
                    diff_addr = int(d.split(' ')[1], 16)
                    if diff_addr in us and diff_addr in ida:
                        if hex(diff_addr) + ': ' + ida[diff_addr] + ' vs ' + us[diff_addr] not in differing:
                            differing.append(hex(diff_addr) + ': ' + ida[diff_addr] + ' vs ' + us[diff_addr])
                    elif diff_addr in us:
                        excl_us.append(hex(diff_addr) + ': ' + us[diff_addr])
                    elif diff_addr in ida:
                        excl_ida.append(hex(diff_addr) + ': ' + ida[diff_addr])

                if not differing and not excl_ida and not excl_us:
                    print()
                    print('Function matches, but mask mismatched:')
                    print('Expected Mask:', mask)
                    print('Actual Mask  :', actual[addr][2].hex())

                print()

                if differing:
                    print('Differing instructions (expected vs actual):')
                    print('\n'.join(sorted(differing, key=lambda s: int(s.split(':')[0], 16))))
                if excl_ida:
                    print('Only on IDA:')
                    print('\n'.join(sorted(excl_ida, key=lambda s: int(s.split(':')[0], 16))))
                if excl_us:
                    print('Only on ghidra:')
                    print('\n'.join(sorted(excl_us, key=lambda s: int(s.split(':')[0], 16))))

                print()
            
            miss+=1

    print('Checked', len(expected), 'functions in', end - start,'seconds (' + str(missing) + ' missing), Mismatch:', str(miss) + '; Accuracy:', (len(expected)-miss)/len(expected))


if __name__ == "__main__":
    import sys
    check_against_ida(input(), int(val) if (val:=input()) else 2, 'x86') #only x86 is supported atm