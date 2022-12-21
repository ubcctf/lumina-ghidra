
from lumina_structs import *
from ghidra.util import Msg
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.database.function import FunctionDB
from ghidra.program.database import ProgramDB

import socket, ssl, threading

from .sig.util import ARCH_MAPPING
from .parsing import apply_md, craft_push_md, craft_pull_md


class LuminaClient:
    def __init__(self, plugin) -> None:
        self.socket = None
        self.lock = threading.RLock() #we need RLock to be able to enter critical sections holding a lock already
        self.plugin = plugin
        self.reconnect()

    def is_valid(self, ctx: ProgramDB):
        #ghidra doesnt allow multi arch disassembly so no function specific context needed
        return self.socket and ctx.getLanguage().getProcessor().toString() in ARCH_MAPPING
    
    def send_and_recv_rpc(self, code: RPC_TYPE, noretry: bool = False, **kwargs):
        try: 
            with self.lock: #only lock if not already in critical section (see reconnect())
                payload = rpc_message_build(code, **kwargs)
                Msg.debug(self.plugin, 'Sending ' + str(code) + ' command (' + str(payload) + ')')
                self.socket.send(payload)

                packet, message = rpc_message_parse(self.socket)
                Msg.debug(self.plugin, 'Received ' + str(packet) + 'Message: ' + str(message) + '')
                return packet, message
        except (ConnectionError, con.StreamError) as e:
            Msg.warn(self.plugin, 'Disconnected from the Lumina server.' + ('' if noretry else ' Reconnecting...'))
            if not noretry:
                self.reconnect()
                return self.send_and_recv_rpc(code, **kwargs)  #retry
            return (None, None)
        except Exception as e:
            Msg.error(self.plugin, 'Something went wrong: ' + str(type(e)) + ': ' + str(e))
            return (None, None)


    def reconnect(self, *_):  #ignore additional args
        with self.lock:  #lock until handshakes over to avoid other reqs go faster than we do
            try:
                if self.socket:  #reset connection
                    self.socket.close()

                settings = self.plugin.getTool().getOptions("Lumina")   #refresh settings

                host = settings.getString('Host Address', ''), int(settings.getString('Port', ''))

                self.socket = socket.socket()
                self.socket.connect(host)

                cert = settings.getFile('TLS Certificate File', None)
                if cert:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cert.getPath())
                    self.socket = context.wrap_socket(self.socket, server_hostname=host[0])

                key, id = b'', bytes(6)
                try:
                    keyfile = settings.getFile('Key File', None)
                    if keyfile:
                        with open(keyfile.getPath(), 'rb') as kf:
                            key = kf.read()
                            if key.startswith(b'HEXRAYS_LICENSE'):    #looks like genuine license, parse id
                                #id is from the line with IDAPRO*W in it
                                id = bytes.fromhex(key.split(b' IDAPRO')[0].split(b'\n')[-1].replace(b'-', b'').decode())
                                if len(id) != 6:   #must be 6 bytes long, if not something went wrong
                                    id = bytes(6)  #reset into empty bytes
                                    raise ValueError()
                except OSError:
                    Msg.warn(self.plugin, 'Lumina key file path is invalid, ignoring...')
                except ValueError:
                    Msg.warn(self.plugin, 'Given Hexrays license file seems malformed, skipping parsing...')

                #dont retry for this query to prevent infinite mutual recursion
                resp, msg = self.send_and_recv_rpc(RPC_TYPE.RPC_HELO, noretry=True, protocol=2, hexrays_license=key, hexrays_id=id, field_0x36=0)
                if not resp or resp.code != RPC_TYPE.RPC_OK:
                    raise ConnectionError('Handshake failed ' + (f'({msg.message})' if resp and resp.code == RPC_TYPE.RPC_FAIL else '(Connection failure)'))

                Msg.info(self.plugin, 'Connection to Lumina server ' +  host[0] + ':' + str(host[1]) + ' (TLS: ' + str(bool(cert)) + ') succeeded.')
            except Exception as e:
                if self.socket:  #if we got an error after opening the socket, close it; also needs to be locked
                    self.socket.close()
                self.socket = None

                Msg.showWarn(self.plugin, None, 'Lumina connection failed', 'Connection to Lumina server failed (' + (str(e) if type(e) != ValueError else 'invalid port') + '). Please check your configuration.')

    
    #
    # All functions commands
    #

    def pull_all_mds(self, ctx: ProgramDB):
        #background in this context is in the pythread - all commands get queued into that thread
        Msg.info(self.plugin, "Pulling all function metadata in the background...")

        #just in case functions changed while we were waiting, make a copy since we rely on ordering heavily
        #also coz otherwise it returns a java array which is hard to use lol
        copy = list(ctx.getFunctionManager().getFunctions(True))

        tool = self.plugin.getTool()

        pull = craft_pull_md(ctx, copy, tool)

        #TODO use Command class so we get a nicer status update panel
        #(if possible; we aren't using their task queue so im not sure)
        tool.setStatusInfo('[Lumina] Sending pull request...')

        msg = self.send_and_recv_rpc(RPC_TYPE.PULL_MD, **pull)[1]

        tool.setStatusInfo('[Lumina] Applying metadata...')

        if msg:
            it = iter(msg.results) #also results only have valid mds so its easier to model with iterator
            for i, found in enumerate(msg.found):
                if not found: #0 means found for some reason? 
                    apply_md(ctx, copy[i], next(it))
            log = 'Pulled ' + str(len(msg.found) - sum(msg.found)) + '/' + str(len(msg.found)) + ' functions successfully.'
            Msg.info(self.plugin, log)
            tool.setStatusInfo('[Lumina] ' + log)
        else:
            #it doesnt matter if the status is always there its better than not being able to see it at all
            tool.setStatusInfo('[Lumina] Pull request for all functions failed.')


    def push_all_mds(self, ctx: ProgramDB):
        Msg.info(self.plugin, "Pushing all function metadata in the background...")

        tool = self.plugin.getTool()

        kwargs = craft_push_md(ctx, list(ctx.getFunctionManager().getFunctions(True)), tool)
        
        tool.setStatusInfo('[Lumina] Sending push request...')

        msg = self.send_and_recv_rpc(RPC_TYPE.PUSH_MD, **kwargs)[1]

        if msg:
            log = 'Pushed ' + str(sum(msg.resultsFlags)) + '/' + str(len(msg.resultsFlags)) + ' functions successfully.'
            Msg.info(self.plugin, log)
            tool.setStatusInfo('[Lumina] ' + log)
        else:
            tool.setStatusInfo('[Lumina] Push request for all functions failed.')


    #
    # Function specific commands
    #

    def pull_function_md(self, ctx: ProgramDB, func: FunctionDB):
        Msg.debug(self.plugin, 'Pulling metadata for func ' + func.getName() + '...')

        msg = self.send_and_recv_rpc(RPC_TYPE.PULL_MD, **craft_pull_md(ctx, [func]))[1]

        #status info kinda nice for displaying subtle msgs to the user that's not lost in the logs
        #so lets do it even for the function specific commands
        tool = self.plugin.getTool()

        if msg and msg.results:
            apply_md(ctx, func, msg.results[0])
            log = 'Pulled metadata for function "' + func.getName() + '" successfully.'
            Msg.info(self.plugin, log)
            tool.setStatusInfo('[Lumina] ' + log)
        else:
            tool.setStatusInfo('[Lumina] Pull request for the function failed.')
                

    def push_function_md(self, ctx: ProgramDB, func: FunctionDB):
        Msg.debug(self.plugin, 'Pushing metadata for func ' + func.getName() + '...')

        msg = self.send_and_recv_rpc(RPC_TYPE.PUSH_MD, **craft_push_md(ctx, [func]))[1]

        tool = self.plugin.getTool()

        if msg:
            log = 'Pushed metadata for function "' + func.getName() + '" successfully.'
            Msg.info(self.plugin, log)
            tool.setStatusInfo('[Lumina] ' + log)
        else:
            tool.setStatusInfo('[Lumina] Push request for the function failed.')