package wireguard

import (
	"github.com/idy/wgc/internal/logger"
	"github.com/idy/wgc/internal/netutil"
)

// ErrInvalidPacket identifies malformed or unauthenticated input.
var ErrInvalidPacket = netutil.ErrInvalidPacket

// SetLogHandler replaces the process-wide log output. Verbosity is -2 for
// errors, -1 for warnings, 0 for normal messages, and positive for debug detail.
// The handler must be safe for concurrent calls. A nil handler restores the
// standard log package and suppresses positive verbosity levels.
func SetLogHandler(handler func(verbosity int, message string)) {
	logger.SetHandler(handler)
}
