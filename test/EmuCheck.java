// Runs the p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program is emu.bin imported raw (code addresses in the tests are short-word addresses).
// Script args: <tests.txt> <outfile> [ctx:<field>=<value>@<start-hex>-<end-hex> ...]
//   tests.txt lines: <name> <start-hex> <stop-hex> <init|-> <expect>
//   init/expect items: reg=hex, m<size>:<addr-hex>=hex (code space) or d<size>:<word-addr-hex>=hex
//   (the dm space, 32-bit words; big-endian memory of 4/8 bytes)
//   An expect item TRAP=<name> means the program must stop at a pcodeop (a hardware trap or bus
//   operation) with that name instead of reaching the stop address; the other items are then
//   checked against the state at that point.
// A test whose name starts with XFAIL_ must be reported as failing: it proves that the checks can fail.
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		for (int i = 2; i < args.length; i++) {
			if (args[i].startsWith("ctx:")) {
				String[] p = args[i].substring(4).split("[=@-]");
				currentProgram.getProgramContext().setValue(currentProgram.getRegister(p[0]),
					codeAddr(Long.parseUnsignedLong(p[2], 16)), codeAddr(Long.parseUnsignedLong(p[3], 16)),
					new BigInteger(p[1]));
			}
		}
		int pass = 0, fail = 0, xfail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			String[] f = line.split("\\s+");
			String err = runOne(f);
			boolean expectFail = f[0].startsWith("XFAIL_");
			if (expectFail) {
				if (err == null) {
					fail++;
					out.println("FAIL " + f[0] + ": the deliberately wrong expectation was accepted");
				}
				else {
					xfail++;
					out.println("PASS " + f[0] + " (wrong expectation detected: " + err + ")");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed, %d broken expectations detected%n", pass, fail,
			xfail);
		out.close();
	}

	private Address memAddr(String item) {
		long off = Long.parseUnsignedLong(item.substring(item.indexOf(':') + 1), 16);
		if (item.startsWith("d")) {
			return currentProgram.getAddressFactory().getAddressSpace("dm").getTruncatedAddress(off, true);
		}
		return codeAddr(off);
	}

	/** An address in the default (code) space from its addressable-unit offset. */
	private Address codeAddr(long off) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getTruncatedAddress(off, true);
	}

	private Register reg(String name) {
		Register r = currentProgram.getRegister(name);
		if (r == null) {
			r = currentProgram.getRegister(name.toUpperCase());
		}
		if (r == null) {
			throw new IllegalArgumentException("no register " + name);
		}
		return r;
	}

	private String runOne(String[] f) throws Exception {
		Address start = codeAddr(Long.parseUnsignedLong(f[1], 16));
		Address stop = codeAddr(Long.parseUnsignedLong(f[2], 16));
		// disassemble first, so that DO loops mark their loop ends (globalset context)
		if (getInstructionAt(start) == null) {
			disassemble(start);
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					set(emu, kv);
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getAddressableWordOffset());
			String trap = null;
			for (String kv : f[4].split(",")) {
				if (kv.startsWith("TRAP=")) {
					trap = kv.substring(5);
				}
			}
			// Step one instruction at a time with the program's stored context: Ghidra's
			// EmulatorHelper clears non-flowing context bits between instructions, so the
			// visa mode and the DO loop-end marks (both non-flowing) would be lost otherwise.
			emu.writeRegister(emu.getPCRegister(), start.getAddressableWordOffset());
			Address cur = start;
			boolean ok = true;
			for (int n = 0; n < 200000 && !cur.equals(stop); n++) {
				emu.setContextRegister(currentProgram.getProgramContext().getDisassemblyContext(cur));
				ok = emu.step(monitor);
				cur = emu.getExecutionAddress();
				if (!ok) {
					break;
				}
			}
			boolean reached = ok && cur.equals(stop);
			if (trap != null) {
				String err = String.valueOf(emu.getLastError());
				if (emu.getEmulateExecutionState() != EmulateExecutionState.FAULT || !err.contains(trap)) {
					return "expected a trap in " + trap + " but state is " + emu.getEmulateExecutionState() +
						" at " + emu.getExecutionAddress() + " (" + err + ")";
				}
			}
			else if (!reached) {
				return "did not reach " + stop + " (state " + emu.getEmulateExecutionState() + " at " +
					emu.getExecutionAddress() + ", " + emu.getLastError() + ")";
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].equals("-") ? new String[0] : f[4].split(",")) {
				if (kv.startsWith("TRAP=")) {
					continue;
				}
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got;
				if ((p[0].startsWith("m") || p[0].startsWith("d")) && p[0].contains(":")) {
					int size = Integer.parseInt(p[0].substring(1, p[0].indexOf(':')));
					Address a = memAddr(p[0]);
					byte[] b = emu.readMemory(a, size);
					got = BigInteger.ZERO;
					for (int i = 0; i < size; i++) {
						got = got.shiftLeft(8).or(BigInteger.valueOf(b[i] & 0xff));
					}
					want = want.and(BigInteger.ONE.shiftLeft(size * 8).subtract(BigInteger.ONE));
				}
				else {
					Register r = reg(p[0]);
					BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
					want = want.and(mask);
					got = emu.readRegister(r).and(mask);
				}
				if (!want.equals(got)) {
					bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	private void set(EmulatorHelper emu, String kv) throws Exception {
		String[] p = kv.split("=");
		BigInteger v = new BigInteger(p[1], 16);
		if ((p[0].startsWith("m") || p[0].startsWith("d")) && p[0].contains(":")) {
			int size = Integer.parseInt(p[0].substring(1, p[0].indexOf(':')));
			Address a = memAddr(p[0]);
			byte[] b = new byte[size];
			for (int i = 0; i < size; i++) {
				b[i] = v.shiftRight(8 * (size - 1 - i)).byteValue();
			}
			emu.writeMemory(a, b);
		}
		else {
			emu.writeRegister(reg(p[0]), v);
		}
	}
}
