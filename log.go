package wireguard

import (
	"fmt"
	"time"

	"github.com/idy/wgc/internal/logger"
)

type logContext interface {
	logPrefix() string
}

type logV struct {
	logger.Verbose
	context logContext
}

func (l logV) Print(text string) {
	l.PrintLazy(func() string { return l.context.logPrefix() + "]" + text })
}

func (l logV) Printf(format string, v ...interface{}) {
	l.PrintLazy(func() string { return fmt.Sprintf(l.context.logPrefix()+"] "+format, v...) })
}

func (conn *Conn) logPrefix() string {
	return "wg_" + conn.staticPub.String()[:5]
}

func (p *peer) logPrefix() string {
	return fmt.Sprintf("wg_%s p_%s",
		p.conn.staticPub.String()[:5],
		p.staticPub.String()[:5],
	)
}

func (w *peerWriter) logPrefix() string {
	p := w.peer
	return fmt.Sprintf("wg_%s p_%s w%d:%v",
		p.conn.staticPub.String()[:5],
		p.staticPub.String()[:5],
		len(w.data),
		w.time.Sub(w.start).Truncate(time.Second),
	)
}

func (w *initiationWriter) logPrefix() string {
	s := w.session
	p := s.peer
	return fmt.Sprintf("wg_%s p_%s s%d iw:%.2fs",
		p.conn.staticPub.String()[:5],
		p.staticPub.String()[:5],
		s.sender,
		w.time.Sub(w.start).Seconds(),
	)
}

func (msg *inboundMessage) logPrefix() string {
	if msg.session == nil {
		return msg.conn.logPrefix()
	}
	s := msg.session
	return fmt.Sprintf("wg_%s p_%s s%d m%v",
		msg.conn.staticPub.String()[:5],
		s.peer.staticPub.String()[:5],
		s.sender,
		msg.typ,
	)
}

func (conn *Conn) logV(l logger.Level) logV {
	return logV{Verbose: logger.V(l), context: conn}
}

func (p *peer) logV(l logger.Level) logV {
	return logV{Verbose: logger.V(l), context: p}
}

func (w *peerWriter) logV(l logger.Level) logV {
	return logV{Verbose: logger.V(l), context: w}
}

func (w *initiationWriter) logV(l logger.Level) logV {
	return logV{Verbose: logger.V(l), context: w}
}

func (msg *inboundMessage) logV(l logger.Level) logV {
	return logV{Verbose: logger.V(l), context: msg}
}

func (r *cookieReply) logV(l logger.Level) logV          { return (*inboundMessage)(r).logV(l) }
func (hi *handshakeInitiation) logV(l logger.Level) logV { return (*inboundMessage)(hi).logV(l) }
func (hr *handshakeResponse) logV(l logger.Level) logV   { return (*inboundMessage)(hr).logV(l) }
func (td *transportData) logV(l logger.Level) logV       { return (*inboundMessage)(td).logV(l) }
