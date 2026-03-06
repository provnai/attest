//go:build linux && cgo
// +build linux,cgo

package bridge

/*
#cgo LDFLAGS: -lattest_rs -lssl -lcrypto -ltss2-esys -ltss2-mu -ltss2-tctildr -lm -ldl -lpthread
*/
import "C"
