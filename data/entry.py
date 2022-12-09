__package__ = 'data'   #hotfix for relative imports

from .client import LuminaClient

from ghidra.framework.options import OptionType


settings = plugin.getTool().getOptions("Lumina")     #already creates the category if doesnt exist for us

#only register if not in keys already
if not settings.isRegistered('Host Address'):
    settings.registerOption('Host Address', OptionType.STRING_TYPE, '', None, 'Host address for the Lumina server')
    settings.registerOption('Port', OptionType.INT_TYPE, -1, None, 'Port for the Lumina server')
    settings.registerOption('Key File', OptionType.FILE_TYPE, '', None, 'Path to the Key file to connect to the Lumina server with, if any')
    settings.registerOption('TLS Certificate File', OptionType.FILE_TYPE, '', None, 'Path to the TLS Certificate for the Lumina server, if any')


#try logging in with configured params
client = LuminaClient(plugin, settings)

#TODO option for reverting applied metadata
PluginCommand.register_for_function('Lumina\\Pull current function metadata', 'Obtain function info from Lumina server', client.pull_function_md, client.is_valid)
PluginCommand.register_for_function('Lumina\\Push current function metadata', 'Push function info to Lumina server', client.push_function_md, client.is_valid)

PluginCommand.register('Lumina\\Pull all function metadata', 'Obtain all function info from Lumina server', client.pull_all_mds, client.is_valid)
PluginCommand.register('Lumina\\Push all function metadata', 'Push all function info to Lumina server', client.push_all_mds, client.is_valid)

PluginCommand.register('Lumina\\Reconnect', 'Reconnect to the lumina server with new configuration', client.reconnect)