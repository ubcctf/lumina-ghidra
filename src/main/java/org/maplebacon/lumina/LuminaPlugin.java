package org.maplebacon.lumina;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.NoSuchElementException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuBarData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.jar.ResourceFile;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidrathon.GhidrathonPlugin;
import ghidrathon.interpreter.GhidrathonInterpreter;
import resources.Icons;

@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "lumina",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Lumina implementation for Ghidra",
	description = "This plugin adds support for IDA's Lumina feature in Ghidra.",
	servicesRequired = { ConsoleService.class },    //needed to ensure console initiates first
	eventsConsumed = { ProgramLocationPluginEvent.class }  //needed to get currentLocation updates
)
public class LuminaPlugin extends ProgramPlugin {
	private GhidrathonInterpreter python;
	private File pyScripts;

	public LuminaPlugin(PluginTool tool) throws IOException {
		super(tool, false, false);
		
		//unzip the python files into extension directory if not done yet so python can read it properly
		//getFile implicitly copies to the application directory that we want
		pyScripts = Application.getModuleDataSubDirectory(".").getFile(true);
	}
	
	@Override
	protected void init() {
		//start the lumina client
		try {
			python = GhidrathonInterpreter.get();
			ResourceFile entry = Arrays.asList(pyScripts.listFiles()).stream().filter(f -> f.getName().equals("entry.py")).map(f -> new ResourceFile(f)).findFirst().get();
			
			//set any errors to print to the console; it is expected that all communciations should be done through Msg logger but for debugging purposes this would be much more visible
			ConsoleService console = tool.getService(ConsoleService.class);
			python.setStreams(console.getStdOut(), console.getStdErr());
			
			python.set("plugin", this);   //pass everything we need to do the plugin in python; getTool will give us the rest we need			
			python.runScript(entry);		
		} catch(NoSuchElementException e) {
			python.close();
			python = null;
			Msg.error(this, "Lumina python scripts not found:", e);
		}
		
		createActions();

	}
	
	private DockingAction getLuminaAction(String name, String exec, boolean checkValid, boolean funcSpecific) {
		MenuData tb = new MenuData(new String[] {"Lumina", name});
		DockingAction action = new DockingAction(name, "Lumina") {
			@Override
			public void actionPerformed(ActionContext context) {
				if(python != null) {					
					python.set("ctx", currentProgram);
					if(funcSpecific)   //only set if its function specific - can be null otherwise
						python.set("func", currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress()));
					//Msg is probably not in scope, so we import
					python.eval(exec + (checkValid ? " if client.is_valid(ctx) else __import__('ghidra.util').util.Msg.showWarn(plugin, None, 'Lumina - Unavailable', 'This function is not available in this context. (Either the client is not connected, or the architecture is currently unsupported.)')" : ""));
				} else {
					Msg.showWarn(LuminaPlugin.this, null, "Lumina - inconsistent state", "The python interpreter is not available right now. Please restart the plugin.");
				}
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !checkValid || (currentProgram != null && currentLocation != null && !(funcSpecific && currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress()) == null));
			}
		};
		action.setMenuBarData(tb);
		action.setEnabled(true);
		action.markHelpUnnecessary();
		return action;
	}
	
	
	private void createActions() {
		if(tool.getDockingActionsByOwnerName("Lumina").size() == 0) {   //only add if not added already
			tool.addAction(getLuminaAction("Pull current function metadata", "client.pull_function_md(ctx, func)", true, true));
			tool.addAction(getLuminaAction("Push current function metadata", "client.push_function_md(ctx, func)", true, true));
			tool.addAction(getLuminaAction("Pull all function metadata", "client.pull_all_mds(ctx)", true, false));
			tool.addAction(getLuminaAction("Push all function metadata", "client.push_all_mds(ctx)", true, false));
			tool.addAction(getLuminaAction("Reconnect", "client.reconnect()", false, false));
			//TODO option for reverting applied metadata
		}
	}
	
	@Override
	protected void dispose() {
		if(python != null) 
			python.close();      //need to close it at the end in case we need to turn lumina back on (which is likely in the same thread as before aka jep is gonna die)
	}
	
}
