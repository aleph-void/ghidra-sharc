// Decode the first instruction of every fixed-size slot of the imported raw image (no analysis).
// Output, one line per slot:  "<slot-index> <length> <instruction text>"   (length 0 = no valid decode)
// Script args: <outfile> <slot-size> [pcode|nopcode [first-slot [end-slot]]]
//
// Ghidra caches instruction prototypes under a 32-bit CRC of the constructor tree and trusts the
// CRC to be unique (SleighLanguage.instructProtoMap).  The corpora here hold a few hundred
// thousand distinct trees, so CRC collisions are certain; the cache is cleared after every slot so
// that each slot is decoded from scratch.  (A collision in real use decodes an instruction with
// another instruction's prototype; see GHIDRA-RARE.md.)
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Field;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.pcode.PcodeOp;

public class DumpSlots extends GhidraScript {

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
		PrintStream out = new PrintStream(args[0]);
		int slot = Integer.parseInt(args[1]);
		boolean pcode = args.length > 2 && args[2].equals("pcode");
		long first = args.length > 3 ? Long.parseLong(args[3]) : 0;
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		long n = block.getSize() / slot;
		if (args.length > 4) {
			n = Math.min(n, Long.parseLong(args[4]));
		}
		Language lang = currentProgram.getLanguage();
		Map<?, ?> protoCache = null;
		try {
			Field fld = lang.getClass().getDeclaredField("instructProtoMap");
			fld.setAccessible(true);
			protoCache = (Map<?, ?>) fld.get(lang);
		}
		catch (ReflectiveOperationException e) {
			println("warning: cannot reach the prototype cache: " + e);
		}
		for (long i = first; i < n; i++) {
			Address a = base.add(i * slot);
			String text;
			int len = 0;
			PseudoInstruction ins = null;
			try {
				ProcessorContext ctx = new ProgramProcessorContext(currentProgram.getProgramContext(), a);
				MemBuffer buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
				InstructionPrototype p = lang.parse(buf, ctx, false);
				ins = new PseudoInstruction(currentProgram, a, p, buf, ctx);
				len = ins.getLength();
				text = ins.toString();
			}
			catch (Exception e) {
				text = "BAD";
			}
			out.printf("%d %d %s%n", i, len, text);
			if (pcode && ins != null) {
				for (PcodeOp op : ins.getPcode()) {
					out.printf("    %s%n", op);
				}
			}
			if (protoCache != null) {
				protoCache.clear();
			}
		}
		out.close();
	}
}
