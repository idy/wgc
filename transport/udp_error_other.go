//go:build !windows

package transport

func isDatagramTooLarge(error) bool {
	return false
}
