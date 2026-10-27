// Decode every slot of a raw image and record which SLEIGH constructors (by source line) appear in
// the decoded parse trees: the "every entry is reachable" check.  Output: one <file>:<line> per line.
// Script args: <outfile> <slot-size>
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;

public class Reach extends GhidraScript {

	private final TreeSet<String> seen = new TreeSet<>();

	private void walk(ConstructState st) {
		if (st.getConstructor() != null) {
			seen.add(st.getConstructor().getSourceFile() + ":" + st.getConstructor().getLineno());
		}
		for (int i = 0; i < st.getNumSubStates(); i++) {
			ConstructState sub = st.getSubState(i);
			if (sub != null) {
				walk(sub);
			}
		}
	}

	@Override
	protected void run() throws Exception {
		String[] all = getScriptArgs();
		List<String> rest = new ArrayList<>();
		MemoryBlock blk0 = currentProgram.getMemory().getBlocks()[0];
		for (String a : all) {
			// "ctx:<field>=<value>" sets a context field over the whole image before decoding
			if (a.startsWith("ctx:")) {
				String[] kv = a.substring(4).split("=");
				Register r = currentProgram.getRegister(kv[0]);
				currentProgram.getProgramContext().setValue(r, blk0.getStart(), blk0.getEnd(),
					new BigInteger(kv[1]));
			}
			else {
				rest.add(a);
			}
		}
		String[] args = rest.toArray(new String[0]);
		int slot = Integer.parseInt(args[1]);
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		long n = block.getSize() / slot;
		Language lang = currentProgram.getLanguage();
		Field fld = lang.getClass().getDeclaredField("instructProtoMap");
		fld.setAccessible(true);
		Map<?, ?> protoCache = (Map<?, ?>) fld.get(lang);
		// "sweep:<field>:<lo>:<hi>" decodes every slot once per value of a context field
		String sweep = args.length > 2 ? args[2] : null;
		int lo = 0, hi = 0;
		Register sreg = null;
		if (sweep != null && sweep.startsWith("sweep:")) {
			String[] p = sweep.split(":");
			sreg = currentProgram.getRegister(p[1]);
			lo = Integer.parseInt(p[2]);
			hi = Integer.parseInt(p[3]);
		}
		for (int v = lo; v <= hi; v++) {
		if (sreg != null) {
			currentProgram.getProgramContext().setValue(sreg, block.getStart(), block.getEnd(),
				BigInteger.valueOf(v));
		}
		for (long i = 0; i < n; i++) {
			Address a = base.add(i * slot);
			try {
				ProcessorContext ctx = new ProgramProcessorContext(currentProgram.getProgramContext(), a);
				MemBuffer buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
				InstructionPrototype p = lang.parse(buf, ctx, false);
				walk(((SleighInstructionPrototype) p).getRootState());
			}
			catch (Exception e) {
				// not an instruction
			}
			protoCache.clear();
		}
		}
		PrintStream out = new PrintStream(args[0]);
		for (String l : seen) {
			out.println(l);
		}
		out.close();
	}
}
