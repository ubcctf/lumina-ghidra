package org.maplebacon.lumina;

import java.io.PrintWriter;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import generic.jar.ResourceFile;
import ghidrathon.interpreter.GhidrathonInterpreter;
import ghidrathon.GhidrathonConfig;
import ghidrathon.GhidrathonUtils;

/**
 * The class responsible for executing python code,
 * ensuring consistency of the thread state for jep. <br>
 * <br>
 * This class abstracts with a single thread executor, which means commands submitted are executed sequentially,
 * ensuring the ordering is as expected.
 * @author despawningbone
 */
public class PythonExecutor {
	private GhidrathonInterpreter python;
	private ExecutorService pyThread;
	
	//TODO figure out whether this will introduces noticable race conditions due to modifying program state (are transactions thread safe?)
	
	/**
	 * Instantiates the environment for the python interpreter.
	 */
	public PythonExecutor(PrintWriter out, PrintWriter err) {
		BasicThreadFactory factory = new BasicThreadFactory.Builder()
				.namingPattern("Lumina-JEP-thread-%d")
				.priority(7)   //higher than norm, lower than critical
				.build();
		
		pyThread = Executors.newSingleThreadExecutor(factory);
		
		final GhidrathonConfig config = GhidrathonUtils.getDefaultGhidrathonConfig();
		config.addStdOut(out);
		config.addStdErr(err);

		try {  //wait until it finishes
			pyThread.submit(() -> python = GhidrathonInterpreter.get(config)).get();
		} catch (InterruptedException | ExecutionException e) {
			python = null;   //disable on error
		}
	}
	
	
	/**
	 * Evaluates a python statement, blocking until it finishes.
	 * @apiNote Assumes isEnabled == true
	 * @param line python statement to execute
	 */
	public void evalSync(String line) {
		try {
			pyThread.submit(() -> python.eval(line)).get();
		} catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);   //pass exception to our own thread in unchecked fashion, as would happen without executor
		}	
	}

	/**
	 * Evaluates a python statement asynchronously.
	 * @apiNote Assumes isEnabled == true
	 * @param line python statement to execute
	 */
	public void eval(String line) {
		pyThread.execute(() -> python.eval(line));
	}

	
	/**
	 * Evaluates a python script, blocking until it finishes.
	 * @apiNote Assumes isEnabled == true
	 * @param file python script to execute
	 */
	public void runScriptSync(ResourceFile file) {
		try {
			pyThread.submit(() -> python.runScript(file)).get();
		} catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);   //pass exception to our own thread in unchecked fashion, as would happen without executor
		}	
	}

	/**
	 * Evaluates a python script asynchronously.
	 * @apiNote Assumes isEnabled == true
	 * @param file python script to execute
	 */
	public void runScript(ResourceFile line) {
		pyThread.execute(() -> python.runScript(line));
	}	
	
	
	/**
	 * Passes a value to the python interpreter.
	 */
	public void set(String name, Object obj) {  //we dont really need a sync method for this since we dont really care about when it finishes and the ordering is already guaranteed
		pyThread.execute(() -> python.set(name, obj));
	}
	
	
	/**
	 * Checks whether the python environment is available.
	 * @return whether the python interpreter is ready
	 */
	public boolean isEnabled() {
		return python != null;
	}
	
	
	/**
	 * Cleans up the python environment and disables it.
	 */
	public void close() {
		try {
			pyThread.submit(() -> python.close()).get();
			pyThread.shutdown();
			python = null;
		} catch (InterruptedException | ExecutionException e) {
			;  //its whatever we can just ignore it we are leaving anyway; a new PythonExecutor will have a new thread for the python state
		}
	}
}
