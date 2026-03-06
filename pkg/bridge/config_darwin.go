//go:build darwin && cgo
// +build darwin,cgo

package bridge

/*
#cgo LDFLAGS: -lattest_rs -framework Security -framework CoreFoundation
*/
import "C"
