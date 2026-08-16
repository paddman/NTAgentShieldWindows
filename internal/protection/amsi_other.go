//go:build !windows

package protection

import (
	"context"
	"errors"
)

type amsiResult struct {
	Malware bool
	Name    string
}

func scanAMSI(context.Context, string, []byte) (amsiResult, error) {
	return amsiResult{}, errors.New("AMSI is available only on Windows")
}
