package client

import (
	"bytes"
	"errors"
	"io"
	"strconv"

	"github.com/heainframework/heain-sdk/heain"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func asCallError(err error, ce **heain.CallError) bool { return errors.As(err, ce) }
