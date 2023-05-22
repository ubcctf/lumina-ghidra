import sys

#hotfix for win32com SetupEnvironment NoneType is not callable; we are effectively running a bundled python installation anyway
sys.frozen = 1

from .client import LuminaClient

from ghidra.framework.options import OptionType
from ghidra.program.model.symbol import SourceType
from ghidra.util import SystemUtilities
from org.maplebacon.lumina import SourceTypeEditor

#ALWAYS register to prevent weird behaviours of resetting config - see removeUnusedOptions() implementation in ToolOptions
#Also apparently storing as INT_TYPE might trigger !isCompatibleOption - the value retrieved from the XML is returned as a Long whereas they expect an int
#seems like that's coz jep stores python integers as longs, so whatever we can just make it a string
settings = plugin.getTool().getOptions("Lumina")     #already creates the category if doesnt exist for us
settings.registerOption('Host Address', OptionType.STRING_TYPE, '', None, 'Host address for the Lumina server')
settings.registerOption('Port', OptionType.STRING_TYPE, '', None, 'Port for the Lumina server')
#also needs to use None instead of an empty string as path here since that would be incompatible with java.io.File
settings.registerOption('Key File', OptionType.FILE_TYPE, None, None, 'Path to the Key file to connect to the Lumina server with, if any')
settings.registerOption('TLS Certificate File', OptionType.FILE_TYPE, None, None, 'Path to the TLS Certificate for the Lumina server, if any')

# sort the displayed source types by priority
min_editor = None
max_editor = None
if not SystemUtilities.isInHeadlessMode():
    min_editor = SourceTypeEditor()
    max_editor = SourceTypeEditor()

# TODO: better names?
settings.registerOption('Minimum Metadata Level To Push', OptionType.ENUM_TYPE, SourceType.USER_DEFINED, None, 'Push metadata with a source priority at least this high', min_editor)
settings.registerOption('Maximum Metadata Level To Override On Pull', OptionType.ENUM_TYPE, SourceType.IMPORTED, None, 'On pull, do not override any existing metadata with a source priority strictly higher than this', max_editor)

#try logging in with configured params
plugin.setClient(LuminaClient(plugin))
