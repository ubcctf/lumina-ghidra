
from lumina_structs import *
from ghidra.util import Msg
from ghidra.program.database.function import FunctionDB
from ghidra.program.flatapi import FlatProgramAPI

import socket, ssl, threading

from .sig.util import ARCH_MAPPING
from .parsing import apply_md, craft_push_md, craft_pull_md


class LuminaClient:
    def __init__(self, plugin, settings) -> None:
        self.socket = None
        self.lock = threading.RLock() #we need RLock to be able to enter critical sections holding a lock already
        self.plugin = plugin
        self.settings = settings
        self.reconnect()
    
    def send_and_recv_rpc(self, code: RPC_TYPE, **kwargs):
        try: 
            with self.lock: #only lock if not already in critical section (see reconnect())
                payload = rpc_message_build(code, **kwargs)
                Msg.debug(self.plugin, 'Sending ' + str(code) + ' command (' + str(payload) + ')')
                self.socket.send(payload)

                packet, message = rpc_message_parse(self.socket)
                Msg.debug(self.plugin, 'Received ' + str(packet) + 'Message: ' + str(message) + '')
                return packet, message
        except (ConnectionError, con.StreamError):
            Msg.warn(self.plugin, 'Disconnected from the Lumina server. Reconnecting...')
            self.reconnect()
            return self.send_and_recv_rpc(code, **kwargs)  #retry
        except Exception as e:
            Msg.error(self.plugin, 'Something went wrong: ' + str(type(e)) + ': ' + str(e))
            return (None, None)


    def reconnect(self, *_):  #ignore additional args
        with self.lock:  #lock until handshakes over to avoid other reqs go faster than we do
            try:
                if self.socket:  #reset connection
                    self.socket.close()

                host = self.settings.getString('Host Address', ''), self.settings.getInt('Port', 0)

                print(host)

                self.socket = socket.socket()
                self.socket.connect(host)

                cert = self.settings.getFile('Key File', None)
                if cert:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cert.getPath())
                    self.socket = context.wrap_socket(self.socket, server_hostname=host[0])

                try:
                    keyfile = self.settings.getFile('TLS Certificate File', None)
                    if keyfile:
                        with open(keyfile.getPath(), 'rb') as kf:
                            key = kf.read()
                    else:
                        key = b''
                except OSError:
                    Msg.warn(self.plugin, 'Lumina key file path is invalid, ignoring...')
                    key = b''

                #TODO reverse hexrays id and watermark to support genuine IDA licenses?
                if(self.send_and_recv_rpc(RPC_TYPE.RPC_HELO, protocol=2, hexrays_license=key, hexrays_id=0, watermark=0, field_0x36=0)[0].code != RPC_TYPE.RPC_OK):
                    raise ConnectionError('Handshake failed (Invalid key?)')

                Msg.info(self.plugin, 'Connection to Lumina server ' +  host[0] + ':' + str(host[1]) + ' (TLS: ' + str(bool(cert)) + ') succeeded.')
            except Exception as e:
                if self.socket:  #if we got an error after opening the socket, close it; also needs to be locked
                    self.socket.close()
                self.socket = None

                Msg.showWarn(self.plugin, None, 'Lumina connection failed', 'Connection to Lumina server failed (' + (str(e) if type(e) != ValueError else 'invalid port') + '). Please check your configuration.')

    
    #
    # All functions commands
    #

    def pull_all_mds(self, prog: FlatProgramAPI):
        Msg.info(self.plugin, "Pulling all function metadata in the background...")

        copy = list(bv.functions)  #just in case functions changed while we were waiting, make a copy since we rely on ordering heavily
        send_and_recv_rpc = self.send_and_recv_rpc

        class RunPull(BackgroundTaskThread):
            def run(self):
                #TODO figure out if using bv has race conditions
                for kwargs in craft_pull_md(bv, copy, self):
                    self.progress = '[Lumina] Sending pull request...'

                    msg = send_and_recv_rpc(RPC_TYPE.PULL_MD, **kwargs)[1]

                    self.progress = '[Lumina] Applying metadata...'

                    if msg:
                        it = iter(msg.results) #also results only have valid mds so its easier to model with iterator
                        for i, found in enumerate(msg.found):
                            if not found: #0 means found for some reason? 
                                apply_md(bv, copy[i], next(it))
                        Msg.info(self.plugin, 'Pulled ' + str(len(msg.found) - sum(msg.found)) + '/' + str(len(msg.found)) + ' functions successfully.')

        RunPull('[Lumina] Pulling metadata...', True).start()  #doesnt matter if we copy or not here


    def push_all_mds(self, prog: FlatProgramAPI):
        Msg.info(self.plugin, "Pushing all function metadata in the background...")

        send_and_recv_rpc = self.send_and_recv_rpc
        
        class RunPush(BackgroundTaskThread):
            def run(self):
                kwargs = craft_push_md(bv, bv.functions)
                
                self.progress = '[Lumina] Sending push request...'

                msg = send_and_recv_rpc(RPC_TYPE.PUSH_MD, **kwargs)[1]

                if msg:
                    Msg.info(self.plugin, 'Pushed ' + str(sum(msg.resultsFlags)) + '/' + str(len(msg.resultsFlags)) + ' functions successfully.')

        RunPush('[Lumina] Pushing metadata...', True).start()  #doesnt matter if we copy or not here

    #TODO test if we can get worker_enqueue working so we can calc metadata on a thread each
    #so that pulling all metadata wont be this slow for big binaries somehow
    #just calling worker_enqueue(lambda: self.push_function_md(bv, f)) introduces race conditions on f

    #
    # Function specific commands
    #

    def pull_function_md(self, prog: FlatProgramAPI, func: FunctionDB):
        Msg.debug(self.plugin, 'Pulling metadata for func ' + func.name + '...')

        #TODO pop up saying "pulling function metadata..."?
        msg = self.send_and_recv_rpc(RPC_TYPE.PULL_MD, **(craft_pull_md(bv, [func])[0]))[1]

        if msg:
            apply_md(bv, func, msg.results[0])
            Msg.info(self.plugin, 'Pulled metadata for function "' + func.name + '" successfully.')
                

    def push_function_md(self, prog: FlatProgramAPI, func: FunctionDB):
        Msg.debug(self.plugin, 'Pushing metadata for func ' + func.name + '...')

        msg = self.send_and_recv_rpc(RPC_TYPE.PUSH_MD, **craft_push_md(bv, [func]))[1]

        if msg:
            Msg.info(self.plugin, 'Pushed metadata for function "' + func.name + '" successfully.')