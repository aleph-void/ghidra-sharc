/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sets the language's {@code simd} context over code that runs in SIMD mode.
 * <p>
 * SIMD mode is the run-time bit PEYEN (bit 21) of MODE1.  Compiled and run-time code switch it
 * on and off around short sequences with {@code BIT SET MODE1 0x200000} and
 * {@code BIT CLR MODE1 0x200000}; the change takes effect one instruction later (Programming
 * Reference, "SIMD Mode": one cycle of latency, which the code fills with a NOP).  This analyzer
 * follows those instructions in address order through each function (SISD at entry, as the C
 * run time requires), and re-disassembles the instructions in between with {@code simd} = 1.
 * It does not follow other writes to MODE1 or flow between functions; set {@code simd} by
 * hand for such code.
 */
public class SharcSimdModeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "SHARC SIMD Mode";
	private static final String DESCRIPTION =
		"Sets the simd context over code between BIT SET MODE1 PEYEN and BIT CLR MODE1 PEYEN.";
	private static final long PEYEN = 1L << 21;
	private static final Pattern BIT =
		Pattern.compile("^BIT (SET|CLR) MODE1 (0x[0-9a-fA-F]+)$");

	public SharcSimdModeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// after the delay-slot and call-idiom analyzers have settled the instruction stream
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return "SHARC".equals(program.getLanguage().getProcessor().toString()) &&
			program.getRegister("simd") != null;
	}

	/** +1 for BIT SET MODE1 with PEYEN, -1 for BIT CLR MODE1 with PEYEN, 0 otherwise. */
	static int toggle(Instruction ins) {
		Matcher m = BIT.matcher(ins.toString().trim());
		if (!m.find() || (Long.decode(m.group(2)) & PEYEN) == 0) {
			return 0;
		}
		return m.group(1).equals("SET") ? 1 : -1;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Register simd = program.getRegister("simd");
		Listing listing = program.getListing();
		AddressSet funcs = new AddressSet();
		for (Instruction ins : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (toggle(ins) != 0) {
				Function f = listing.getFunctionContaining(ins.getMinAddress());
				funcs.add(f == null ? new AddressSet(ins.getMinAddress()) : f.getBody());
			}
		}
		List<AddressRange> on = new ArrayList<>();
		for (AddressRange body : funcs.getAddressRanges()) {
			boolean mode = false;
			int pending = 0, delay = 0;
			Address start = null;
			for (Instruction ins : listing.getInstructions(new AddressSet(body), true)) {
				monitor.checkCancelled();
				if (delay > 0 && --delay == 0) {
					boolean next = pending > 0;
					if (next && !mode) {
						start = ins.getMinAddress();
					}
					else if (!next && mode && start != null) {
						on.add(new AddressRangeImpl(start, ins.getMinAddress().previous()));
						start = null;
					}
					mode = next;
				}
				int t = toggle(ins);
				if (t != 0) {
					pending = t;
					delay = 2;	// the instruction after the BIT op still runs in the old mode
				}
			}
			if (mode && start != null) {
				on.add(new AddressRangeImpl(start, body.getMaxAddress()));
			}
		}
		ProgramContext ctx = program.getProgramContext();
		for (AddressRange r : on) {
			monitor.checkCancelled();
			boolean done = true;
			for (Instruction ins : listing.getInstructions(new AddressSet(r), true)) {
				BigInteger v = ins.getValue(simd, false);
				done &= v != null && v.signum() != 0;
			}
			if (done) {
				continue;
			}
			try {
				listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
				ctx.setValue(simd, r.getMinAddress(), r.getMaxAddress(), BigInteger.ONE);
				new DisassembleCommand(new AddressSet(r), null, true).applyTo(program, monitor);
			}
			catch (Exception e) {
				log.appendMsg(NAME, "Could not set SIMD mode over " + r + ": " + e.getMessage());
			}
		}
		return true;
	}
}
