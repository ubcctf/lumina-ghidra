package org.maplebacon.lumina;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.NoSuchElementException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import generic.jar.ResourceFile;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "org.maplebacon.lumina",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Lumina implementation for Ghidra",
	description = "This plugin adds support for IDA's Lumina feature in Ghidra.",
	servicesRequired = { ConsoleService.class },    //needed to ensure console initiates first for python logging
	eventsConsumed = { ProgramLocationPluginEvent.class }  //needed to get currentLocation updates
)
public class LuminaPlugin extends ProgramPlugin {
	private PythonExecutor python;
	private File pyScripts;
	
	//temporary storage for the LuminaClient pyObject - apparently client could go out of scope for some reason for some installations after entry.py
	private Object client;
	
	//expose for entry.py to be able to persist the client object here
	public void setClient(Object client) {
		this.client = client;
	}

	public LuminaPlugin(PluginTool tool) throws IOException {
		super(tool, false, false);
		
		//unzip the python files into extension directory if not done yet so python can read it properly
		//getFile implicitly copies to the application directory that we want
		pyScripts = Application.getModuleDataSubDirectory(".").getFile(true);
	}
	
	@Override
	protected void init() {
		//start the lumina client; DONE move to a separate thread in case other plugins want to make a jep interpreter on the GUI thread too? (also for running background tasks)
		try {
			//set any errors to print to the console; it is expected that all communciations should be done through Msg logger but for debugging purposes this would be much more visible
			ConsoleService console = tool.getService(ConsoleService.class);
			python = new PythonExecutor(console.getStdOut(), console.getStdErr());

			ResourceFile entry = Arrays.asList(pyScripts.listFiles()).stream().filter(f -> f.getName().equals("entry.py")).map(f -> new ResourceFile(f)).findFirst().get();

			python.set("plugin", this);   //pass everything we need to do the plugin in python; getTool will give us the rest we need

			//hotfix for relative imports
			python.eval("import sys; sys.path.append(r'" +  pyScripts.getParentFile().getParent() +  "'); __package__ = 'data'");
			
			python.runScript(entry);		
		} catch(NoSuchElementException e) {
			Msg.error(this, "Lumina python scripts not found:", e);
		}
		
		createActions();
	}
	
	private DockingAction getLuminaAction(String name, String exec, boolean checkValid, boolean funcSpecific) {
		MenuData tb = new MenuData(new String[] {"Lumina", name});
		DockingAction action = new DockingAction(name, "Lumina") {
			@Override
			public void actionPerformed(ActionContext context) {
				if(python.isEnabled()) {					
					python.set("ctx", currentProgram);
					//pass client back into scope before evaluating
					python.set("client", LuminaPlugin.this.client);
					
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
		if(python.isEnabled()) 
			python.close();      //need to close it at the end in case we need to turn lumina back on (which is likely in the same thread as before aka jep is gonna die)
	}
}
