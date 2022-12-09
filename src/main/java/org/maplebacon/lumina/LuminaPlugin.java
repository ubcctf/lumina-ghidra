package org.maplebacon.lumina;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.NoSuchElementException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidrathon.GhidrathonPlugin;
import ghidrathon.interpreter.GhidrathonInterpreter;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "lumina",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Lumina implementation for Ghidra",
	description = "This plugin adds support for IDA's Lumina feature in Ghidra."//,
	//servicesRequired = { GhidrathonPlugin.class }   //somehow this breaks ghidra since ghidrathon is already loaded?
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
			Msg.error(this, "Lumina python scripts not found:", e);
		}

	}
	
	@Override
	protected void dispose() {
		if(python != null) 
			python.close();      //need to close it at the end in case we need to turn lumina back on (which is likely in the same thread as before aka jep is gonna die)
	}
	
}
