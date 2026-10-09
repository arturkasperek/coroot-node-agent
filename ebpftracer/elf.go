package ebpftracer

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

type Symbol struct {
	s       *elf.Symbol
	f       *ELFFile
	address uint64
}

func (s *Symbol) Name() string {
	return s.s.Name
}

func (s *Symbol) Address() uint64 {
	if s.address == 0 {
		s.address = s.s.Value
		for _, p := range s.f.elf.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}
			if p.Vaddr <= s.s.Value && s.s.Value < (p.Vaddr+p.Memsz) {
				s.address = s.s.Value - p.Vaddr + p.Off
				break
			}
		}
	}
	return s.address
}

func (s *Symbol) ReturnOffsets() ([]int, error) {
	text, reader, err := s.f.getTextSectionAndReader()
	if err != nil {
		return nil, err
	}

	sStart := s.s.Value - text.Addr
	_, err = reader.Seek(int64(sStart), io.SeekStart)
	if err != nil {
		return nil, err
	}
	sBytes := make([]byte, s.s.Size)
	_, err = reader.Read(sBytes)
	if err != nil {
		return nil, err
	}

	offsets := getReturnOffsets(s.f.elf.Machine, sBytes)
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no offsets found")
	}
	return offsets, nil
}

func (s *Symbol) AttachUprobe(exe *link.Executable, prog *ebpf.Program, pid uint32) (link.Link, error) {
	return exe.Uprobe(s.Name(), prog, &link.UprobeOptions{Address: s.Address(), PID: int(pid)})
}

func (s *Symbol) AttachUretprobes(exe *link.Executable, prog *ebpf.Program, pid uint32) ([]link.Link, error) {
	returnOffsets, err := s.ReturnOffsets()
	if err != nil {
		return nil, err
	}
	var links []link.Link
	for _, offset := range returnOffsets {
		l, err := exe.Uprobe(s.Name(), prog, &link.UprobeOptions{Address: s.Address(), Offset: uint64(offset), PID: int(pid)})
		if err != nil {
			return links, err
		}
		links = append(links, l)
	}

	return links, nil
}

type ELFFile struct {
	elf *elf.File
	// resolved are the answers of the lookups so far: the symbol of a name, or nil when the
	// file has no such symbol.
	resolved          map[string]*elf.Symbol
	textSection       *elf.Section
	textSectionReader io.ReadSeeker
}

func OpenELFFile(path string) (*ELFFile, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return &ELFFile{elf: file}, nil
}

// A binary has hundreds of thousands of symbols (821k in the agent's own) and the agent
// looks for two or three of them. debug/elf's Symbols() decodes the whole table into
// []elf.Symbol with a string per name: 216 MB of heap for the agent's binary, enough to
// exceed the memory limit of the agent at startup. The tables are read in place instead:
// the entries one by one, the name of a candidate from the string table into a reused
// buffer. Nothing is kept but the symbols that were asked for.

// symbolTable is a symbol table of the file, .symtab or .dynsym.
type symbolTable struct {
	entries io.Reader
	names   io.ReaderAt // the string table of the entries
	versym  io.ReaderAt // .gnu.version: the versions of the entries of .dynsym, nil for .symtab
	count   int         // the entries, the null symbol included
}

const (
	// a name is read in chunks of this size, up to maxNameLength
	nameChunk     = 256
	maxNameLength = 64 * 1024
	// the "hidden" bit of a symbol version: not the default version of the symbol
	versionHidden = 0x8000
)

func (f *ELFFile) entrySize() int {
	if f.elf.Class == elf.ELFCLASS32 {
		return 16 // Elf32_Sym
	}
	return 24 // Elf64_Sym
}

func sectionReaderAt(s *elf.Section) (io.ReaderAt, error) {
	if s.Flags&elf.SHF_COMPRESSED == 0 {
		return s, nil
	}
	data, err := s.Data()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// symbolTables are .symtab, then .dynsym: the order in which the symbols are looked up. A
// table that holds nothing but the null symbol, or has no string table, is left out.
func (f *ELFFile) symbolTables() []symbolTable {
	var tables []symbolTable
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		section := f.elf.SectionByType(typ)
		if section == nil || int(section.Link) >= len(f.elf.Sections) {
			continue
		}
		count := int(section.Size) / f.entrySize()
		if count <= 1 {
			continue
		}
		names, err := sectionReaderAt(f.elf.Sections[section.Link])
		if err != nil {
			continue
		}
		table := symbolTable{entries: bufio.NewReaderSize(section.Open(), 1<<16), names: names, count: count}
		if typ == elf.SHT_DYNSYM {
			if versym := f.elf.SectionByType(elf.SHT_GNU_VERSYM); versym != nil {
				table.versym, _ = sectionReaderAt(versym)
			}
		}
		tables = append(tables, table)
	}
	return tables
}

// decodeSymbol reads the fields of one table entry.
func (f *ELFFile) decodeSymbol(entry []byte) (name uint32, sym elf.Symbol) {
	order := f.elf.ByteOrder
	name = order.Uint32(entry[0:4])
	if f.elf.Class == elf.ELFCLASS32 {
		sym.Value = uint64(order.Uint32(entry[4:8]))
		sym.Size = uint64(order.Uint32(entry[8:12]))
		sym.Info, sym.Other = entry[12], entry[13]
		sym.Section = elf.SectionIndex(order.Uint16(entry[14:16]))
		return
	}
	sym.Info, sym.Other = entry[4], entry[5]
	sym.Section = elf.SectionIndex(order.Uint16(entry[6:8]))
	sym.Value = order.Uint64(entry[8:16])
	sym.Size = order.Uint64(entry[16:24])
	return
}

// isCallable says whether a symbol is a function that can be probed.
func isCallable(sym *elf.Symbol) bool {
	return elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Size != 0 && sym.Value != 0
}

// isHiddenVersion says whether entry i of a .dynsym is a non-default version of a symbol
// (libpthread has pthread_cond_timedwait twice: a default and a compatibility one).
func (f *ELFFile) isHiddenVersion(table *symbolTable, i int) bool {
	if table.versym == nil {
		return false
	}
	var version [2]byte
	if _, err := table.versym.ReadAt(version[:], int64(i)*2); err != nil {
		return false
	}
	return f.elf.ByteOrder.Uint16(version[:])&versionHidden != 0
}

var errNoSymbols = errors.New("no symbols found")

// lookup finds the symbols of names in one pass over the tables and remembers the answers.
// The first function of a name wins, .symtab before .dynsym; of the versions of a dynamic
// symbol only the default one counts.
func (f *ELFFile) lookup(names []string) error {
	pending := map[string]struct{}{}
	longest := 0
	for _, name := range names {
		if _, ok := f.resolved[name]; !ok {
			pending[name] = struct{}{}
			longest = max(longest, len(name))
		}
	}
	if len(pending) == 0 {
		return nil
	}
	tables := f.symbolTables()
	if len(tables) == 0 {
		return errNoSymbols
	}
	if f.resolved == nil {
		f.resolved = map[string]*elf.Symbol{}
	}

	entry := make([]byte, f.entrySize())
	// longest + 1 bytes: a name of the table is a match only when the terminator follows it
	buf := make([]byte, longest+1)
	for t := range tables {
		table := &tables[t]
		for i := 0; i < table.count && len(pending) > 0; i++ {
			if _, err := io.ReadFull(table.entries, entry); err != nil {
				return fmt.Errorf("read symbols: %w", err)
			}
			if i == 0 { // the null symbol
				continue
			}
			nameOffset, sym := f.decodeSymbol(entry)
			if !isCallable(&sym) {
				continue
			}
			n, _ := table.names.ReadAt(buf, int64(nameOffset))
			end := bytes.IndexByte(buf[:n], 0)
			if end < 0 {
				continue
			}
			if _, ok := pending[string(buf[:end])]; !ok {
				continue
			}
			if f.isHiddenVersion(table, i) {
				continue
			}
			found := sym // a copy: the symbol of the loop must not escape to the heap, one per entry
			found.Name = string(buf[:end])
			f.resolved[found.Name] = &found
			delete(pending, found.Name)
		}
	}
	for name := range pending {
		f.resolved[name] = nil
	}
	return nil
}

// PrefetchSymbols looks the names up in one pass over the symbol tables, so that GetSymbol
// of each of them does not read the file again. Whoever needs several symbols of a file
// (the Go TLS probes need three, Node.js six) should call it first.
func (f *ELFFile) PrefetchSymbols(names ...string) {
	_ = f.lookup(names)
}

func (f *ELFFile) GetSymbol(name string) (*Symbol, error) {
	if _, ok := f.resolved[name]; !ok {
		if err := f.lookup([]string{name}); err != nil {
			return nil, err
		}
	}
	es := f.resolved[name]
	if es == nil {
		return nil, fmt.Errorf("symbol %s not found", name)
	}
	return &Symbol{s: es, f: f}, nil
}

func (f *ELFFile) FindSymbolValue(name string) (uint64, error) {
	return findSymbolValue(f.elf, ".symtab", name)
}

func findSymbolValue(ef *elf.File, sectionName, symName string) (uint64, error) {
	section := ef.Section(sectionName)
	if section == nil {
		return 0, fmt.Errorf("no %s section", sectionName)
	}
	strtab := ef.Sections[section.Link]
	if strtab == nil {
		return 0, fmt.Errorf("no string table for %s", sectionName)
	}

	entrySize := int64(24) // Elf64_Sym
	if ef.Class == elf.ELFCLASS32 {
		entrySize = 16 // Elf32_Sym
	}

	symReader := section.Open()
	entry := make([]byte, entrySize)
	target := []byte(symName)
	nameBuf := make([]byte, len(target)+1)

	// skip entry 0 (undefined symbol)
	if _, err := symReader.Read(entry); err != nil {
		return 0, fmt.Errorf("read %s: %w", sectionName, err)
	}

	for {
		if _, err := symReader.Read(entry); err != nil {
			break
		}
		nameIdx := ef.ByteOrder.Uint32(entry[0:4])
		var value uint64
		if ef.Class == elf.ELFCLASS64 {
			value = ef.ByteOrder.Uint64(entry[8:16])
		} else {
			value = uint64(ef.ByteOrder.Uint32(entry[4:8]))
		}
		if nameIdx == 0 {
			continue
		}
		n, _ := strtab.ReadAt(nameBuf, int64(nameIdx))
		if n < len(target) {
			continue
		}
		if n > len(target) && nameBuf[len(target)] != 0 {
			continue
		}
		if string(nameBuf[:len(target)]) == symName {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%s not found", symName)
}

// readName reads the NUL-terminated name at offset of a string table into buf, growing it
// when needed. ok is false when the name has no terminator within maxNameLength.
func readName(names io.ReaderAt, offset int64, buf []byte) (name, grown []byte, ok bool) {
	buf = buf[:0]
	for len(buf) < maxNameLength {
		if cap(buf)-len(buf) < nameChunk {
			buf = append(make([]byte, 0, 2*cap(buf)+nameChunk), buf...)
		}
		chunk := buf[len(buf) : len(buf)+nameChunk]
		n, err := names.ReadAt(chunk, offset+int64(len(buf)))
		if end := bytes.IndexByte(chunk[:n], 0); end >= 0 {
			return buf[:len(buf)+end], buf, true
		}
		buf = buf[:len(buf)+n]
		if err != nil || n == 0 {
			break
		}
	}
	return nil, buf, false
}

func (f *ELFFile) FindSymbolBySubstrings(substrs ...string) *Symbol {
	entry := make([]byte, f.entrySize())
	var buf []byte
	for _, table := range f.symbolTables() {
		for i := 0; i < table.count; i++ {
			if _, err := io.ReadFull(table.entries, entry); err != nil {
				break
			}
			if i == 0 { // the null symbol
				continue
			}
			nameOffset, sym := f.decodeSymbol(entry)
			if !isCallable(&sym) {
				continue
			}
			var name []byte
			var ok bool
			if name, buf, ok = readName(table.names, int64(nameOffset), buf); !ok {
				continue
			}
			match := true
			for _, sub := range substrs {
				if !bytes.Contains(name, []byte(sub)) {
					match = false
					break
				}
			}
			if match {
				found := sym // a copy: the symbol of the loop must not escape to the heap, one per entry
				found.Name = string(name)
				return &Symbol{s: &found, f: f}
			}
		}
	}
	return nil
}

func (f *ELFFile) getTextSectionAndReader() (*elf.Section, io.ReadSeeker, error) {
	if f.textSection == nil {
		f.textSection = f.elf.Section(".text")
		if f.textSection == nil {
			return nil, nil, fmt.Errorf("no .text")
		}
		f.textSectionReader = f.textSection.Open()
	}
	return f.textSection, f.textSectionReader, nil
}

func (f *ELFFile) IsGoBinary() bool {
	return f.elf.Section(".go.buildinfo") != nil
}

func (f *ELFFile) IsRustBinary() bool {
	section := f.elf.Section(".comment")
	if section == nil {
		return false
	}
	data, err := section.Data()
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("rustc version"))
}

func (f *ELFFile) Close() error {
	return f.elf.Close()
}

func getReturnOffsets(machine elf.Machine, instructions []byte) []int {
	var res []int
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, i)
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, i)
			}
			i += 4
		}
	}
	return res
}
