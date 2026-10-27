// Real-code statistics for an analysed program: instruction, function and bookmark counts, decompiler
// failures, and a listing of every disassembled instruction for comparison with a reference.
// Script args: <summary-file> <listing-file> [decompile-limit] [entries-file: lines '<name> <hex address>']
// With an entries file the functions are created and disassembled from those addresses first (raw images).
//@category Testing

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class RealCheck extends GhidraScript {

	private String bytesAt(ghidra.program.model.address.Address a) {
		StringBuilder sb = new StringBuilder();
		try {
			for (int i = 0; i < 6; i++) {
				sb.append(String.format("%02x", currentProgram.getMemory().getByte(a.add(i)) & 0xff));
			}
		}
		catch (Exception e) {
			// end of memory
		}
		return sb.toString();
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream sum = new PrintStream(args[0]);
		PrintStream lst = new PrintStream(args[1]);
		int limit = args.length > 2 ? Integer.parseInt(args[2]) : 200;

		if (args.length > 3) {
			for (String l : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[3]))) {
				String[] f = l.trim().split("\\s+");
				if (f.length < 2) {
					continue;
				}
				ghidra.program.model.address.Address a = toAddr(Long.parseUnsignedLong(f[1], 16));
				disassemble(a);
				createFunction(a, f[0]);
			}
		}
		int insns = 0;
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			insns++;
			lst.printf("%x %d %s%n", ins.getAddress().getOffset(), ins.getLength(), ins.toString());
		}
		lst.close();

		int funcs = 0;
		FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
		while (fi.hasNext()) {
			fi.next();
			funcs++;
		}

		Map<String, Integer> marks = new HashMap<>();
		BookmarkManager bm = currentProgram.getBookmarkManager();
		java.util.Iterator<Bookmark> bi = bm.getBookmarksIterator();
		while (bi.hasNext()) {
			Bookmark b = bi.next();
			String key = b.getTypeString() + "/" + b.getCategory();
			marks.merge(key, 1, Integer::sum);
			if (b.getTypeString().equals("Error") || b.getTypeString().equals("Warning")) {
				sum.printf("%s %s %s %s%n", key, b.getAddress(), b.getComment().replace('\n', ' '),
					bytesAt(b.getAddress()));
			}
		}

		int tried = 0, failed = 0, timedOut = 0;
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		fi = currentProgram.getFunctionManager().getFunctions(true);
		while (fi.hasNext() && tried < limit) {
			Function f = fi.next();
			if (f.isThunk() || f.getBody().getNumAddresses() < 8) {
				continue;
			}
			tried++;
			DecompileResults r = di.decompileFunction(f, 20, monitor);
			if (!r.decompileCompleted()) {
				failed++;
				if (r.isTimedOut()) {
					timedOut++;
				}
				sum.printf("decompile failure at %s: %s%n", f.getEntryPoint(), r.getErrorMessage());
			}
		}
		sum.printf("language %s%n", currentProgram.getLanguageID());
		sum.printf("executable format %s%n", currentProgram.getExecutableFormat());
		sum.printf("blocks %d%n", currentProgram.getMemory().getBlocks().length);
		sum.printf("instructions %d%n", insns);
		sum.printf("functions %d%n", funcs);
		for (Map.Entry<String, Integer> e : new java.util.TreeMap<>(marks).entrySet()) {
			sum.printf("bookmark %s %d%n", e.getKey(), e.getValue());
		}
		sum.printf("decompiled %d failed %d (timed out %d)%n", tried, failed, timedOut);
		sum.close();
	}
}
