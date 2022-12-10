__package__ = 'data'   #hotfix for relative imports

import sys
sys.frozen = 1   #hotfix for win32com SetupEnvironment NoneType is not callable; we are effectively running a bundled python installation anyway

from .client import LuminaClient

from ghidra.framework.options import OptionType


settings = plugin.getTool().getOptions("Lumina")     #already creates the category if doesnt exist for us

#only register if not in keys already
if not settings.isRegistered('Host Address'):
    settings.registerOption('Host Address', OptionType.STRING_TYPE, '', None, 'Host address for the Lumina server')
    settings.registerOption('Port', OptionType.INT_TYPE, 0, None, 'Port for the Lumina server')
    settings.registerOption('Key File', OptionType.FILE_TYPE, '', None, 'Path to the Key file to connect to the Lumina server with, if any')
    settings.registerOption('TLS Certificate File', OptionType.FILE_TYPE, '', None, 'Path to the TLS Certificate for the Lumina server, if any')


#try logging in with configured params
client = LuminaClient(plugin, settings)