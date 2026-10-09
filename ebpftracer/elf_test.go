package ebpftracer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSymbol is one entry of a symbol table written by writeTestELF.
type testSymbol struct {
	name  string
	typ   elf.SymType
	value uint64
	size  uint64
}

func fn(name string, value, size uint64) testSymbol {
	return testSymbol{name: name, typ: elf.STT_FUNC, value: value, size: size}
}

// writeTestELF writes a minimal ELF file with .text, .symtab/.strtab and
// .dynsym/.dynstr. A nil table is left out of the file altogether.
func writeTestELF(t testing.TB, class elf.Class, symtab, dynsym []testSymbol) string {
	t.Helper()
	order := binary.LittleEndian

	type section struct {
		name    string
		typ     elf.SectionType
		link    uint32
		entsize uint64
		data    []byte
	}
	table := func(syms []testSymbol) (symbols, strtab []byte) {
		strtab = []byte{0}
		entry := func(name uint32, typ elf.SymType, value, size uint64) []byte {
			var b bytes.Buffer
			info := byte(elf.STB_GLOBAL)<<4 | byte(typ)
			if class == elf.ELFCLASS64 {
				_ = binary.Write(&b, order, name)
				b.WriteByte(info)
				b.WriteByte(0)
				_ = binary.Write(&b, order, uint16(1))
				_ = binary.Write(&b, order, value)
				_ = binary.Write(&b, order, size)
			} else {
				_ = binary.Write(&b, order, name)
				_ = binary.Write(&b, order, uint32(value))
				_ = binary.Write(&b, order, uint32(size))
				b.WriteByte(info)
				b.WriteByte(0)
				_ = binary.Write(&b, order, uint16(1))
			}
			return b.Bytes()
		}
		symbols = entry(0, elf.STT_NOTYPE, 0, 0) // the null symbol
		for _, s := range syms {
			symbols = append(symbols, entry(uint32(len(strtab)), s.typ, s.value, s.size)...)
			strtab = append(append(strtab, s.name...), 0)
		}
		return symbols, strtab
	}

	entsize := uint64(24)
	if class == elf.ELFCLASS32 {
		entsize = 16
	}
	sections := []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, data: make([]byte, 16)}}
	if symtab != nil {
		symbols, strtab := table(symtab)
		sections = append(sections,
			section{name: ".symtab", typ: elf.SHT_SYMTAB, link: uint32(len(sections) + 1), entsize: entsize, data: symbols},
			section{name: ".strtab", typ: elf.SHT_STRTAB, data: strtab})
	}
	if dynsym != nil {
		symbols, strtab := table(dynsym)
		sections = append(sections,
			section{name: ".dynsym", typ: elf.SHT_DYNSYM, link: uint32(len(sections) + 1), entsize: entsize, data: symbols},
			section{name: ".dynstr", typ: elf.SHT_STRTAB, data: strtab})
	}
	shstrtab := []byte{0}
	nameOffsets := make([]uint32, len(sections))
	for i := 1; i < len(sections); i++ {
		nameOffsets[i] = uint32(len(shstrtab))
		shstrtab = append(append(shstrtab, sections[i].name...), 0)
	}
	nameOffsets = append(nameOffsets, uint32(len(shstrtab)))
	shstrtab = append(append(shstrtab, ".shstrtab"...), 0)
	sections = append(sections, section{name: ".shstrtab", typ: elf.SHT_STRTAB, data: shstrtab})

	ehsize, shentsize := 64, 64
	if class == elf.ELFCLASS32 {
		ehsize, shentsize = 52, 40
	}
	var body bytes.Buffer
	offsets := make([]uint64, len(sections))
	for i := 1; i < len(sections); i++ {
		offsets[i] = uint64(ehsize + body.Len())
		body.Write(sections[i].data)
	}
	for (ehsize+body.Len())%8 != 0 {
		body.WriteByte(0)
	}
	shoff := uint64(ehsize + body.Len())

	var file bytes.Buffer
	file.Write([]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), 0, 0, 0, 0, 0, 0, 0, 0, 0})
	_ = binary.Write(&file, order, uint16(elf.ET_DYN))
	_ = binary.Write(&file, order, uint16(elf.EM_X86_64))
	_ = binary.Write(&file, order, uint32(elf.EV_CURRENT))
	if class == elf.ELFCLASS64 {
		_ = binary.Write(&file, order, uint64(0)) // entry
		_ = binary.Write(&file, order, uint64(0)) // phoff
		_ = binary.Write(&file, order, shoff)
	} else {
		_ = binary.Write(&file, order, uint32(0))
		_ = binary.Write(&file, order, uint32(0))
		_ = binary.Write(&file, order, uint32(shoff))
	}
	_ = binary.Write(&file, order, uint32(0)) // flags
	_ = binary.Write(&file, order, uint16(ehsize))
	_ = binary.Write(&file, order, uint16(0)) // phentsize
	_ = binary.Write(&file, order, uint16(0)) // phnum
	_ = binary.Write(&file, order, uint16(shentsize))
	_ = binary.Write(&file, order, uint16(len(sections)))
	_ = binary.Write(&file, order, uint16(len(sections)-1)) // shstrndx
	file.Write(body.Bytes())
	for i, s := range sections {
		if class == elf.ELFCLASS64 {
			_ = binary.Write(&file, order, nameOffsets[i])
			_ = binary.Write(&file, order, uint32(s.typ))
			_ = binary.Write(&file, order, uint64(0)) // flags
			_ = binary.Write(&file, order, uint64(0)) // addr
			_ = binary.Write(&file, order, offsets[i])
			_ = binary.Write(&file, order, uint64(len(s.data)))
			_ = binary.Write(&file, order, s.link)
			_ = binary.Write(&file, order, uint32(0)) // info
			_ = binary.Write(&file, order, uint64(1)) // addralign
			_ = binary.Write(&file, order, s.entsize)
		} else {
			_ = binary.Write(&file, order, nameOffsets[i])
			_ = binary.Write(&file, order, uint32(s.typ))
			_ = binary.Write(&file, order, uint32(0))
			_ = binary.Write(&file, order, uint32(0))
			_ = binary.Write(&file, order, uint32(offsets[i]))
			_ = binary.Write(&file, order, uint32(len(s.data)))
			_ = binary.Write(&file, order, s.link)
			_ = binary.Write(&file, order, uint32(0))
			_ = binary.Write(&file, order, uint32(1))
			_ = binary.Write(&file, order, uint32(s.entsize))
		}
	}
	path := filepath.Join(t.TempDir(), "test.elf")
	require.NoError(t, os.WriteFile(path, file.Bytes(), 0o644))
	return path
}

func openTestELF(t testing.TB, path string) *ELFFile {
	t.Helper()
	ef, err := OpenELFFile(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ef.Close() })
	return ef
}

func TestELFGetSymbol(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS64, elf.ELFCLASS32} {
		t.Run(class.String(), func(t *testing.T) {
			ef := openTestELF(t, writeTestELF(t, class,
				[]testSymbol{
					fn("main.handler", 0x1000, 0x40),
					{name: "main.counter", typ: elf.STT_OBJECT, value: 0x2000, size: 8},
					fn("zero_size", 0x3000, 0),
					fn("zero_value", 0, 0x10),
					fn("foobar", 0x4000, 0x20),
					fn("in_both", 0x5000, 0x10),
					fn("last_in_table", 0x6000, 0x10),
				},
				[]testSymbol{
					fn("in_both", 0x9000, 0x99),
					fn("only_dynamic", 0x7000, 0x30),
				}))

			s, err := ef.GetSymbol("main.handler")
			require.NoError(t, err)
			assert.Equal(t, "main.handler", s.Name())
			assert.Equal(t, uint64(0x1000), s.s.Value)
			assert.Equal(t, uint64(0x40), s.s.Size)

			s, err = ef.GetSymbol("only_dynamic")
			require.NoError(t, err)
			assert.Equal(t, uint64(0x7000), s.s.Value, "a symbol that is only in .dynsym")

			s, err = ef.GetSymbol("in_both")
			require.NoError(t, err)
			assert.Equal(t, uint64(0x5000), s.s.Value, ".symtab is searched before .dynsym")

			s, err = ef.GetSymbol("last_in_table")
			require.NoError(t, err)
			assert.Equal(t, uint64(0x6000), s.s.Value, "the last name of the string table is found")

			for _, name := range []string{"main.counter", "zero_size", "zero_value"} {
				_, err = ef.GetSymbol(name)
				assert.EqualError(t, err, "symbol "+name+" not found", "only functions with a size and an address are symbols")
			}
			for _, name := range []string{"foo", "oobar", "foobarr", "", "missing"} {
				_, err = ef.GetSymbol(name)
				assert.Error(t, err, "%q is not a name of the table, only a part of one", name)
			}
		})
	}
}

func TestELFWithoutSymbols(t *testing.T) {
	ef := openTestELF(t, writeTestELF(t, elf.ELFCLASS64, nil, nil))
	_, err := ef.GetSymbol("main.handler")
	assert.EqualError(t, err, "no symbols found")
	assert.Nil(t, ef.FindSymbolBySubstrings("main"))

	ef = openTestELF(t, writeTestELF(t, elf.ELFCLASS64, []testSymbol{}, []testSymbol{}))
	_, err = ef.GetSymbol("main.handler")
	assert.EqualError(t, err, "no symbols found", "tables that hold only the null symbol")
}

func TestELFFindSymbolBySubstrings(t *testing.T) {
	long := "_ZN" + strings.Repeat("a_very_long_mangled_component_", 20) + "rustls6common6Writer5write17h0123456789abcdefE" // > 600 bytes
	ef := openTestELF(t, writeTestELF(t, elf.ELFCLASS64,
		[]testSymbol{
			fn("rustls::Writer::flush", 0x1000, 0),
			fn("rustls::Reader::read", 0x2000, 0x10),
			fn(long, 0x3000, 0x50),
			{name: "rustls::Writer::write_obj", typ: elf.STT_OBJECT, value: 0x4000, size: 8},
		},
		[]testSymbol{fn("dyn_rustls_Reader_read_vectored", 0x5000, 0x10)}))

	s := ef.FindSymbolBySubstrings("rustls", "Reader", "read")
	require.NotNil(t, s)
	assert.Equal(t, "rustls::Reader::read", s.Name(), "the first match of the table")
	assert.Equal(t, uint64(0x2000), s.s.Value)

	s = ef.FindSymbolBySubstrings("rustls", "Writer", "write")
	require.NotNil(t, s, "a function with a size and an address; the zero-size and the object ones are skipped")
	assert.Equal(t, long, s.Name(), "a name longer than any read buffer is returned whole")
	assert.Equal(t, uint64(0x3000), s.s.Value)
	assert.Equal(t, uint64(0x50), s.s.Size)

	s = ef.FindSymbolBySubstrings("Reader", "vectored")
	require.NotNil(t, s)
	assert.Equal(t, "dyn_rustls_Reader_read_vectored", s.Name(), ".dynsym is searched too")

	assert.Nil(t, ef.FindSymbolBySubstrings("rustls", "Nothing"))
}

// The reason for reading the table in place: a binary has hundreds of thousands
// of symbols and the agent looks for two or three of them. Materializing all of
// them took 216 MB of heap for the agent's own binary and made the agent exceed
// its 1 GiB memory limit at startup.
func TestELFGetSymbolDoesNotAllocatePerSymbol(t *testing.T) {
	const symbols = 100000
	table := make([]testSymbol, symbols)
	for i := range table {
		table[i] = fn(fmt.Sprintf("pkg/path.(*Type%d).Method", i), uint64(0x1000+i*0x10), 0x10)
	}
	path := writeTestELF(t, elf.ELFCLASS64, table, nil)

	allocs := testing.AllocsPerRun(3, func() {
		ef, err := OpenELFFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer ef.Close()
		s, err := ef.GetSymbol(fmt.Sprintf("pkg/path.(*Type%d).Method", symbols-1))
		if err != nil || s.s.Value != uint64(0x1000+(symbols-1)*0x10) {
			t.Fatalf("symbol: %v %v", s, err)
		}
	})
	// The count is of the whole process, so tests that run in the same binary (a tracer
	// with its readers) add some thousands. The bound is a tenth of the symbols: reading the
	// table into memory costs two allocations per symbol.
	assert.Less(t, allocs, float64(symbols/10), "allocations of one lookup in a table of %d symbols", symbols)
}

// referenceSymbol is what GetSymbol did before it read the table in place:
// every symbol of .symtab, then every symbol of .dynsym, as debug/elf decodes
// them, and the first function with a size and an address that has the name and
// is not a hidden (non-default) version.
func referenceSymbol(f *elf.File, name string) (elf.Symbol, bool) {
	symbols, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	for _, s := range append(symbols, dyn...) {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
			continue
		}
		if s.Name == name && s.VersionIndex&0x8000 == 0 {
			return s, true
		}
	}
	return elf.Symbol{}, false
}

// realELFFiles are this binary (a Go executable with a .symtab) and the system
// libraries, which have versioned symbols where a hidden compatibility version
// of a function sits next to its default one.
func realELFFiles(t testing.TB) []string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	files := []string{self}
	for _, pattern := range []string{
		"/lib/x86_64-linux-gnu/libc.so.*", "/lib/x86_64-linux-gnu/libm.so.*", "/lib/x86_64-linux-gnu/libpthread.so.*",
		"/usr/lib/x86_64-linux-gnu/libssl.so.*",
	} {
		matches, _ := filepath.Glob(pattern)
		files = append(files, matches...)
	}
	return files
}

// interestingNames are the names to look up in a real file: every name that the
// tables list more than once (the versions), a sample of the others and two that
// are not there. hidden is how many of them have a hidden (non-default) version.
func interestingNames(path string) (names []string, hidden int) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	symbols, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	all := append(symbols, dyn...)

	count := map[string]int{}
	hiddenNames := map[string]bool{}
	for _, s := range all {
		count[s.Name]++
		if s.VersionIndex&0x8000 != 0 {
			hiddenNames[s.Name] = true
		}
	}
	seen := map[string]bool{}
	for i, s := range all {
		if s.Name == "" || seen[s.Name] {
			continue
		}
		if count[s.Name] > 1 || i%97 == 0 {
			seen[s.Name] = true
			names = append(names, s.Name)
			if hiddenNames[s.Name] {
				hidden++
			}
		}
	}
	return append(names, "no_such_symbol_in_any_binary", ""), hidden
}

func TestELFGetSymbolMatchesDebugElf(t *testing.T) {
	compared, hiddenCompared := 0, 0
	for _, path := range realELFFiles(t) {
		names, hidden := interestingNames(path)
		if len(names) <= 2 {
			continue
		}
		hiddenCompared += hidden
		t.Run(filepath.Base(path), func(t *testing.T) {
			ref, err := elf.Open(path)
			require.NoError(t, err)
			defer ref.Close()
			ef := openTestELF(t, path)
			for _, name := range names {
				want, wantOK := referenceSymbol(ref, name)
				got, err := ef.GetSymbol(name)
				if !wantOK {
					assert.Error(t, err, "%q: not a symbol, got one", name)
					continue
				}
				if !assert.NoError(t, err, "%q", name) {
					continue
				}
				assert.Equal(t, want.Name, got.Name(), "%q", name)
				assert.Equal(t, want.Value, got.s.Value, "%q value", name)
				assert.Equal(t, want.Size, got.s.Size, "%q size", name)
				compared++
			}
		})
	}
	t.Logf("compared %d symbols, %d of the names have a hidden version", compared, hiddenCompared)
	assert.NotZero(t, compared, "no symbol of any file was compared")
	if _, err := os.Stat("/lib/x86_64-linux-gnu/libc.so.6"); err == nil {
		assert.NotZero(t, hiddenCompared, "libc has versioned symbols, so the hidden versions must be part of the comparison")
	}
}
