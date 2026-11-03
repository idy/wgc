package transport

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isDatagramTooLarge(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
