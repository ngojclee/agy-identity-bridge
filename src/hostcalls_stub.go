//go:build !cgo

package main

// callHost keeps unit tests runnable on hosts without a C compiler. Production
// dynamic-library builds use the C-ABI implementation in main.go.
func callHost(method string, payload []byte) ([]byte, bool) {
	return nil, false
}
