package api

import "testing"

func TestByteRange(t *testing.T) {
	cases := []struct {
		h           string
		size        int64
		from, to    int64
		partial, ok bool
	}{
		{"", 100, 0, 100, false, true},
		{"bytes=0-", 100, 0, 100, true, true},
		{"bytes=10-19", 100, 10, 20, true, true},
		{"bytes=90-500", 100, 90, 100, true, true},
		{"bytes=-30", 100, 70, 100, true, true},
		{"bytes=-300", 100, 0, 100, true, true},
		{"bytes=100-", 100, 0, 0, false, false},
		{"bytes=-0", 100, 0, 0, false, false},
		{"bytes=5-1", 100, 0, 100, false, true},
		{"bytes=0-1,5-6", 100, 0, 100, false, true},
		{"items=0-1", 100, 0, 100, false, true},
	}
	for _, c := range cases {
		f, to, p, ok := byteRange(c.h, c.size)
		if f != c.from || to != c.to || p != c.partial || ok != c.ok {
			t.Errorf("%q/%d: got %d-%d %v %v, want %d-%d %v %v", c.h, c.size, f, to, p, ok, c.from, c.to, c.partial, c.ok)
		}
	}
}
