package gobbc

// UntilError execute all func until error returned
func UntilError(fns ...func() error) error {
	for _, fn := range fns {
		if e := fn(); e != nil {
			return e
		}
	}
	return nil
}

// CopyReverse copy and reverse []byte
func CopyReverse(bs []byte) []byte {
	s := make([]byte, len(bs))
	copy(s, bs)
	return reverseBytes(s)
}

// reverseBytes reverse []byte s, and return s
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
