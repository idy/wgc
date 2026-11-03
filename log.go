package wireguard

import (
	"fmt"
	"time"

	"github.com/idy/wgc/internal/logger"
)

type logV struct {
	logger.Verbose
	s string
}

func (l *logV) Print(text string) {
	l.PrintDepth(1, l.s+"]", text)
}

func (l *logV) Printf(format string, v ...interface{}) {
	l.PrintfDepth(1, l.s+"] "+format, v...)
}

func (conn *Conn) logV(l logger.Level) *logV {
	return &logV{
		Verbose: logger.V(l),

		s: "wg_" + conn.staticPub.String()[:5],
	}
}

func (p *peer) logV(l logger.Level) *logV {
	conn := p.conn
	return &logV{
		Verbose: logger.V(l),
		s: fmt.Sprintf("wg_%s p_%s",
			conn.staticPub.String()[:5],
			p.staticPub.String()[:5],
		),
	}
}

func (w *peerWriter) logV(l logger.Level) *logV {
	var (
		p = w.peer
		c = p.conn
	)
	return &logV{
		Verbose: logger.V(l),
		s: fmt.Sprintf("wg_%s p_%s w%d:%v",
			c.staticPub.String()[:5],
			p.staticPub.String()[:5],
			len(w.data),
			w.time.Sub(w.start).Truncate(time.Second),
		),
	}
}

func (w *initiationWriter) logV(l logger.Level) *logV {
	var (
		s = w.session
		p = s.peer
		c = p.conn
	)
	return &logV{
		Verbose: logger.V(l),
		s: fmt.Sprintf("wg_%s p_%s s%d iw:%.2fs",
			c.staticPub.String()[:5],
			p.staticPub.String()[:5],
			s.sender,
			w.time.Sub(w.start).Seconds(),
		),
	}
}

func (msg *inboundMessage) logV(l logger.Level) *logV {
	if msg.session == nil {
		return msg.conn.logV(l)
	}
	var (
		s = msg.session
		p = s.peer
		c = msg.conn
	)
	return &logV{
		Verbose: logger.V(l),
		s: fmt.Sprintf("wg_%s p_%s s%d m%v",
			c.staticPub.String()[:5],
			p.staticPub.String()[:5],
			s.sender,
			msg.typ,
		),
	}
}

func (r *cookieReply) logV(l logger.Level) *logV          { return (*inboundMessage)(r).logV(l) }
func (hi *handshakeInitiation) logV(l logger.Level) *logV { return (*inboundMessage)(hi).logV(l) }
func (hr *handshakeResponse) logV(l logger.Level) *logV   { return (*inboundMessage)(hr).logV(l) }
func (td *transportData) logV(l logger.Level) *logV       { return (*inboundMessage)(td).logV(l) }
