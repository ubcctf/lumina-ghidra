__package__ = 'data'   #hotfix for relative imports

import sys
sys.frozen = 1   #hotfix for win32com SetupEnvironment NoneType is not callable; we are effectively running a bundled python installation anyway

from .client import LuminaClient

from ghidra.framework.options import OptionType


#ALWAYS register to prevent weird behaviours of resetting config - see removeUnusedOptions() implementation in ToolOptions
#Also apparently storing as INT_TYPE might trigger !isCompatibleOption - the value retrieved from the XML is returned as a Long whereas they expect an int
#seems like that's coz jep stores python integers as longs, so whatever we can just make it a string
settings = plugin.getTool().getOptions("Lumina")     #already creates the category if doesnt exist for us
settings.registerOption('Host Address', OptionType.STRING_TYPE, '', None, 'Host address for the Lumina server')
settings.registerOption('Port', OptionType.STRING_TYPE, '', None, 'Port for the Lumina server')
#also needs to use None instead of an empty string as path here since that would be incompatible with java.io.File
settings.registerOption('Key File', OptionType.FILE_TYPE, None, None, 'Path to the Key file to connect to the Lumina server with, if any')
settings.registerOption('TLS Certificate File', OptionType.FILE_TYPE, None, None, 'Path to the TLS Certificate for the Lumina server, if any')

#try logging in with configured params
client = LuminaClient(plugin)