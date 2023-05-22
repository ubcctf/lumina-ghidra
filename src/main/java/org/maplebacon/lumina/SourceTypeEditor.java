package org.maplebacon.lumina;

import java.util.Arrays;

import ghidra.framework.options.EnumEditor;
import ghidra.program.model.symbol.SourceType;

/** Types are not sorted by priority in SourceType, so this editor simply sorts them by priority for display */
public class SourceTypeEditor extends EnumEditor {

	public SourceTypeEditor() {
		super();
	}

	@Override
	public SourceType[] getEnums() {
		SourceType[] values = SourceType.values();
		Arrays.sort(values, (a, b) -> a.isHigherPriorityThan(b) ? 1 : -1);
		return values;
	}

	@Override
	public String[] getTags() {
		return Arrays.stream(getEnums()).map(SourceType::name).toArray(String[]::new);
	}
}
