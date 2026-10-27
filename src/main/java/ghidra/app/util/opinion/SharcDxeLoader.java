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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads an Analog Devices SHARC ADSP-214xx executable (.dxe), the ELF file the VisualDSP++ /
 * CrossCore Embedded Studio linker writes ({@code e_machine} 0x85).  Ghidra's ELF loader cannot
 * place its sections: their addresses are in the processor's units, and their contents are
 * stored per memory width.  Written from the files themselves (no format document is
 * published):
 * <ul>
 * <li>{@code .segmentInfo} (type 0x70000003) lists the linker's memory segments as 24-byte
 * records {start, end, kind, ?, name, width in bits}; a section takes the width of the
 * segment that holds its address;</li>
 * <li>48-bit sections (code at a 48-bit address) hold 6 bytes per word, most significant
 * first;</li>
 * <li>sections in the short-word range hold 16-bit parcels, most significant first (VISA
 * code, 16-bit data);</li>
 * <li>all others hold one 40-bit word (5 bytes) per normal-word address; the 32-bit word is
 * the first four bytes, most significant first, the fifth is the 40-bit extension.</li>
 * </ul>
 * The sections are written into the same memory model as the boot-stream loader (see
 * {@link SharcLdrLoader}), so code and data appear exactly as on the part after booting.
 * Symbols from {@code .symtab} become labels (functions for STT_FUNC with a size), the ELF entry point an
 * entry point.  Executables carry no relocations; relocatable objects (.doj) are refused.
 */
public class SharcDxeLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "ADI SHARC Executable (DXE)";
	private static final LanguageCompilerSpecPair LANGUAGE =
		new LanguageCompilerSpecPair("SHARC:BE:32:214xx", "default");
	private static final int EM_SHARC = 0x85;
	private static final int ET_EXEC = 2;
	private static final int SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_NOBITS = 8;
	private static final int SHT_SEGINFO = 0x70000003;
	private static final int SHF_ALLOC = 2, SHF_EXEC = 4;
	private static final int MAX_FILE = 256 << 20;

	@Override
	public String getName() {
		return NAME;
	}

	// Loader.getAssociatedFileExtensions() in Ghidra 12.3 and later
	public Collection<String> getAssociatedFileExtensions() {
		return List.of("dxe");
	}

	@Override
	protected boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (provider.length() < 52 || provider.length() > MAX_FILE) {
			return List.of();
		}
		byte[] h = provider.readBytes(0, 52);
		if (h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' || h[4] != 1 || h[5] != 1 ||
			u16(h, 18) != EM_SHARC || u16(h, 16) != ET_EXEC) {
			return List.of();
		}
		byte[] buf = provider.readBytes(0, provider.length());
		String proc = processor(buf);
		// SHARC+ (ADSP-215xx/SC5xx) and the older ADSP-2106x..2136x parts are other cores
		boolean ours = proc == null || proc.startsWith("ADSP-214");
		return List.of(new LoadSpec(this, 0, LANGUAGE, ours));
	}

	static int u16(byte[] b, int o) {
		return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8);
	}

	static long u32(byte[] b, int o) {
		return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8) | ((b[o + 2] & 0xffL) << 16) |
			((b[o + 3] & 0xffL) << 24);
	}

	static long be(byte[] b, int o, int n) {
		long v = 0;
		for (int k = 0; k < n; k++) {
			v = (v << 8) | (b[o + k] & 0xff);
		}
		return v;
	}

	/** One ELF section header. */
	record Section(String name, int type, long flags, long addr, int offset, int size, int link) {
	}

	static List<Section> sections(byte[] b) throws IOException {
		int shoff = (int) u32(b, 0x20);
		int shentsize = u16(b, 0x2e), shnum = u16(b, 0x30), shstrndx = u16(b, 0x32);
		if (shoff <= 0 || shentsize < 40 || (long) shoff + (long) shnum * shentsize > b.length) {
			throw new IOException("bad ELF section header table");
		}
		int strOff = (int) u32(b, shoff + shstrndx * shentsize + 16);
		List<Section> out = new ArrayList<>();
		for (int i = 0; i < shnum; i++) {
			int p = shoff + i * shentsize;
			out.add(new Section(cstr(b, strOff + (int) u32(b, p)), (int) u32(b, p + 4),
				u32(b, p + 8), u32(b, p + 12), (int) u32(b, p + 16), (int) u32(b, p + 20),
				(int) u32(b, p + 24)));
		}
		return out;
	}

	static String cstr(byte[] b, int o) {
		int e = o;
		while (e < b.length && b[e] != 0) {
			e++;
		}
		return new String(b, o, e - o, StandardCharsets.ISO_8859_1);
	}

	/** The processor named in {@code .adi.attributes}, e.g. "ADSP-21489". */
	static String processor(byte[] b) {
		try {
			for (Section s : sections(b)) {
				if (s.name.equals(".adi.attributes") && s.offset + s.size <= b.length) {
					String t = new String(b, s.offset, s.size, StandardCharsets.ISO_8859_1);
					int k = t.indexOf("ADSP-");
					if (k >= 0) {
						int e = k;
						while (e < t.length() && t.charAt(e) > ' ' && t.charAt(e) < 0x7f) {
							e++;
						}
						return t.substring(k, e);
					}
				}
			}
		}
		catch (IOException e) {
			// not ours to judge here
		}
		return null;
	}

	/** Width in bits of the memory at address a, from the {@code .segmentInfo} records. */
	static int width(List<long[]> segs, Section s) {
		for (long[] g : segs) {
			if (s.addr >= g[0] && s.addr <= g[1]) {
				return (int) g[2];
			}
		}
		if (SharcLdrLoader.Image.block(s.addr) >= 0) {
			return 16;
		}
		return (s.flags & SHF_EXEC) != 0 ? 48 : 32;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		ByteProvider provider = settings.provider();
		byte[] b = provider.readBytes(0, provider.length());
		List<Section> secs = sections(b);
		List<long[]> segs = new ArrayList<>();
		for (Section s : secs) {
			if (s.type == SHT_SEGINFO) {
				for (int p = s.offset; p + 24 <= s.offset + s.size; p += 24) {
					segs.add(new long[] { u32(b, p), u32(b, p + 4), u32(b, p + 20) });
				}
			}
		}
		SharcLdrLoader.Image image = new SharcLdrLoader.Image();
		// where each section went: {first address, last address, kind} with kind 48 (48-bit
		// address, code at its short-word alias), 16 (short-word address), 32 (normal word)
		Map<Integer, Integer> kinds = new HashMap<>();
		for (int i = 0; i < secs.size(); i++) {
			monitor.checkCancelled();
			Section s = secs.get(i);
			if ((s.flags & SHF_ALLOC) == 0 || (s.type != SHT_PROGBITS && s.type != SHT_NOBITS) ||
				s.size == 0) {
				continue;
			}
			boolean zero = s.type == SHT_NOBITS;
			if (!zero && (long) s.offset + s.size > b.length) {
				throw new IOException("section " + s.name + " runs past the end of the file");
			}
			int w = width(segs, s);
			int kind;
			long n;
			if (w == 48) {
				kind = 48;
				n = s.size / 6;
				for (int k = 0; k < n; k++) {
					image.write48(s.addr + k, zero ? 0 : be(b, s.offset + 6 * k, 6));
				}
			}
			else if (SharcLdrLoader.Image.block(s.addr) >= 0) {
				kind = 16;
				n = s.size / 2;
				for (int k = 0; k < n; k++) {
					image.write16(s.addr + k, zero ? 0 : (int) be(b, s.offset + 2 * k, 2));
				}
			}
			else {
				kind = 32;
				n = s.size / 5;
				for (int k = 0; k < n; k++) {
					image.write32(s.addr + k, zero ? 0 : be(b, s.offset + 5 * k, 4));
				}
			}
			kinds.put(i, kind);
			log.appendMsg(NAME, String.format("%s: 0x%x, %d %d-bit words", s.name, s.addr, n, w));
		}
		try {
			image.create(program, monitor, log);
		}
		catch (Exception e) {
			throw new IOException("could not create the memory of " + provider.getName(), e);
		}
		AddressSpace sw = program.getAddressFactory().getDefaultAddressSpace();
		AddressSpace dm = program.getAddressFactory().getAddressSpace("dm");
		SymbolTable st = program.getSymbolTable();
		for (Section s : secs) {
			if (s.type != SHT_SYMTAB) {
				continue;
			}
			int strOff = secs.get(s.link).offset;
			for (int p = s.offset + 16; p + 16 <= s.offset + s.size; p += 16) {
				String name = cstr(b, strOff + (int) u32(b, p));
				long value = u32(b, p + 4), size = u32(b, p + 8);
				int info = b[p + 12] & 0xff, shndx = u16(b, p + 14);
				int type = info & 0xf;
				Integer kind = kinds.get(shndx);
				if (name.isEmpty() || kind == null || (type != 0 && type != 1 && type != 2)) {
					continue;
				}
				Address a = kind == 48 ? sw.getAddress(SharcLdrLoader.Image.sw48(value), true)
						: kind == 16 ? sw.getAddress(value, true) : dm.getAddress(value, true);
				if (program.getMemory().getBlock(a) == null) {
					continue;
				}
				try {
					st.createLabel(a, name, SourceType.IMPORTED);
					// STT_FUNC with a size is a function; the compiler also types its local
					// code labels (.P<n>L<m>, ___ADI_AGL_CRT_*) STT_FUNC, with size 0
					if (type == 2 && size > 0 && kind != 32) {
						st.addExternalEntryPoint(a);
						program.getFunctionManager().createFunction(name, a, new AddressSet(a),
							SourceType.IMPORTED);
					}
				}
				catch (Exception e) {
					log.appendMsg(NAME, "symbol " + name + ": " + e.getMessage());
				}
			}
		}
		long entry = u32(b, 0x18);
		Address ea = SharcLdrLoader.Image.block(entry) >= 0 ? sw.getAddress(entry, true)
				: sw.getAddress(SharcLdrLoader.Image.sw48(entry), true);
		if (program.getMemory().getBlock(ea) != null) {
			st.addExternalEntryPoint(ea);
		}
	}
}
