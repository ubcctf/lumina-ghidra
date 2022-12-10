__package__ = 'data'   #hotfix for relative imports

import sys
sys.frozen = 1   #hotfix for win32com SetupEnvironment NoneType is not callable; we are effectively running a bundled python installation anyway

from .client import LuminaClient

from ghidra.framework.options import OptionType

print([i for i in plugin.getTool().getOptions()])

#only register if category doesnt exist
if not plugin.getTool().hasOptions("Lumina"):
    settings = plugin.getTool().getOptions("Lumina")     #already creates the category if doesnt exist for us
    settings.registerOption('Host Address', OptionType.STRING_TYPE, '', None, 'Host address for the Lumina server')
    settings.registerOption('Port', OptionType.INT_TYPE, 0, None, 'Port for the Lumina server')
    settings.registerOption('Key File', OptionType.FILE_TYPE, '', None, 'Path to the Key file to connect to the Lumina server with, if any')
    settings.registerOption('TLS Certificate File', OptionType.FILE_TYPE, '', None, 'Path to the TLS Certificate for the Lumina server, if any')
    plugin.getTool().saveTool()

#try logging in with configured params
client = LuminaClient(plugin)