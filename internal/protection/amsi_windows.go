//go:build windows

package protection

import (
	"context"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

type amsiResult struct {
	Malware bool
	Name    string
}

var (
	amsiDLL          = windows.NewLazySystemDLL("amsi.dll")
	amsiInitialize   = amsiDLL.NewProc("AmsiInitialize")
	amsiUninitialize = amsiDLL.NewProc("AmsiUninitialize")
	amsiOpenSession  = amsiDLL.NewProc("AmsiOpenSession")
	amsiCloseSession = amsiDLL.NewProc("AmsiCloseSession")
	amsiScanBuffer   = amsiDLL.NewProc("AmsiScanBuffer")
)

func scanAMSI(ctx context.Context, name string, content []byte) (amsiResult, error) {
	if err := ctx.Err(); err != nil {
		return amsiResult{}, err
	}
	application, _ := windows.UTF16PtrFromString("NTAgentShield")
	contentName, _ := windows.UTF16PtrFromString(name)
	var amsiContext uintptr
	result, _, _ := amsiInitialize.Call(uintptr(unsafe.Pointer(application)), uintptr(unsafe.Pointer(&amsiContext)))
	if int32(result) < 0 || amsiContext == 0 {
		return amsiResult{}, errors.New("AmsiInitialize failed")
	}
	defer amsiUninitialize.Call(amsiContext)
	var session uintptr
	result, _, _ = amsiOpenSession.Call(amsiContext, uintptr(unsafe.Pointer(&session)))
	if int32(result) < 0 {
		return amsiResult{}, errors.New("AmsiOpenSession failed")
	}
	defer amsiCloseSession.Call(amsiContext, session)
	var scanResult uint32
	var pointer uintptr
	if len(content) > 0 {
		pointer = uintptr(unsafe.Pointer(&content[0]))
	}
	result, _, _ = amsiScanBuffer.Call(amsiContext, pointer, uintptr(uint32(len(content))), uintptr(unsafe.Pointer(contentName)), session, uintptr(unsafe.Pointer(&scanResult)))
	if int32(result) < 0 {
		return amsiResult{}, errors.New("AmsiScanBuffer failed")
	}
	malware := scanResult >= 32768
	nameResult := "amsi_clean"
	if malware {
		nameResult = "amsi_malware"
	}
	return amsiResult{Malware: malware, Name: nameResult}, nil
}
