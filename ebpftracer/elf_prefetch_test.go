package ebpftracer

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A caller that needs several symbols of one file (the Go TLS probes need three,
// Node.js six) asks for them in one pass over the table.
func TestELFPrefetchSymbols(t *testing.T) {
	path := writeTestELF(t, elf.ELFCLASS64,
		[]testSymbol{fn("first", 0x1000, 0x10), fn("second", 0x2000, 0x20), fn("unrequested", 0x3000, 0x30)},
		[]testSymbol{fn("dynamic", 0x4000, 0x40)})
	ef, err := OpenELFFile(path)
	require.NoError(t, err)

	ef.PrefetchSymbols("first", "dynamic", "missing", "second")
	require.NoError(t, ef.Close(), "from here on the answers must not need the file")

	for name, value := range map[string]uint64{"first": 0x1000, "second": 0x2000, "dynamic": 0x4000} {
		s, err := ef.GetSymbol(name)
		require.NoError(t, err, name)
		assert.Equal(t, value, s.s.Value, name)
		assert.Equal(t, name, s.Name())
	}
	_, err = ef.GetSymbol("missing")
	assert.EqualError(t, err, "symbol missing not found", "a name that is not in the file is remembered too")
	_, err = ef.GetSymbol("unrequested")
	assert.Error(t, err, "a name that was not prefetched needs the (closed) file and must fail, not panic")
}

func TestELFPrefetchSymbolsOfAFileWithoutSymbols(t *testing.T) {
	ef := openTestELF(t, writeTestELF(t, elf.ELFCLASS64, nil, nil))
	ef.PrefetchSymbols("a", "b")
	_, err := ef.GetSymbol("a")
	assert.EqualError(t, err, "no symbols found")
}

func TestELFPrefetchSymbolsDoesNotAllocatePerSymbol(t *testing.T) {
	const symbols = 100000
	table := make([]testSymbol, symbols)
	for i := range table {
		table[i] = fn(fmt.Sprintf("pkg/path.(*Type%d).Method", i), uint64(0x1000+i*0x10), 0x10)
	}
	path := writeTestELF(t, elf.ELFCLASS64, table, nil)
	names := []string{"pkg/path.(*Type0).Method", fmt.Sprintf("pkg/path.(*Type%d).Method", symbols/2), fmt.Sprintf("pkg/path.(*Type%d).Method", symbols-1)}

	allocs := testing.AllocsPerRun(3, func() {
		ef, err := OpenELFFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer ef.Close()
		ef.PrefetchSymbols(names...)
		for _, name := range names {
			if _, err := ef.GetSymbol(name); err != nil {
				t.Fatal(err)
			}
		}
	})
	// see TestELFGetSymbolDoesNotAllocatePerSymbol for the bound
	assert.Less(t, allocs, float64(symbols/10), "allocations of three lookups in a table of %d symbols", symbols)
}

// The answer of a prefetch is the answer of GetSymbol, and both are the answer
// the whole table decoded by debug/elf gives.
func TestELFPrefetchSymbolsMatchesDebugElf(t *testing.T) {
	compared := 0
	for _, path := range realELFFiles(t) {
		names, _ := interestingNames(path)
		if len(names) <= 2 {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			ref, err := elf.Open(path)
			require.NoError(t, err)
			defer ref.Close()
			ef := openTestELF(t, path)
			ef.PrefetchSymbols(names...)
			for _, name := range names {
				want, wantOK := referenceSymbol(ref, name)
				got, err := ef.GetSymbol(name)
				if !wantOK {
					assert.Error(t, err, "%q", name)
					continue
				}
				if assert.NoError(t, err, "%q", name) {
					assert.Equal(t, want.Value, got.s.Value, "%q value", name)
					assert.Equal(t, want.Size, got.s.Size, "%q size", name)
					compared++
				}
			}
		})
	}
	assert.NotZero(t, compared)
}
