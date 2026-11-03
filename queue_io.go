package wireguard

import (
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/idy/wgc/internal/bufpool"
	"github.com/idy/wgc/internal/header"
	netutils "github.com/idy/wgc/internal/netutil"
)

type Packet struct {
	Data []byte
	msg  *inboundMessage
}

func (pkt *Packet) Release() {
	pkt.Data = nil
	pkt.msg.conn.putInboundMessage(pkt.msg)
}

func (pkt *Packet) From() Peer {
	return pkt.msg.session.peer
}

type readQueueElem struct {
	sync.Mutex
	msg    *inboundMessage
	opened []byte
}

var readQueueElemPool = sync.Pool{
	New: func() interface{} {
		return new(readQueueElem)
	},
}

func newReadQueueElem(conn *Conn) *readQueueElem {
	elem := readQueueElemPool.Get().(*readQueueElem)
	elem.msg = conn.getInboundMessage()
	return elem
}

func (elem *readQueueElem) Release() {
	elem.msg.conn.putInboundMessage(elem.msg)
	elem.msg = nil
	elem.opened = nil
	readQueueElemPool.Put(elem)
}

func (elem *readQueueElem) ReleasePacket() Packet {
	pkt := Packet{elem.opened, elem.msg}
	elem.msg = nil
	elem.opened = nil
	readQueueElemPool.Put(elem)
	return pkt
}

func streamRead(conn *Conn, size int) <-chan Packet {
	var (
		deliveryQueue = make(chan *readQueueElem, size)
		openQueue     = make(chan *readQueueElem, size)
		dataQueue     = make(chan Packet, size)
	)
	go func() {
		defer close(dataQueue)
		for elem := range deliveryQueue {
			elem.Lock()
			//lint:ignore SA2001 Lock to wait for decryption.
			elem.Unlock()
			pkt := elem.ReleasePacket()
			if pkt.Data == nil {
				pkt.Release()
				continue
			}
			select {
			case dataQueue <- pkt:
			case <-conn.done:
				pkt.Release()
			}
		}
		// Reception has stopped; return unread buffers still owned by the queue.
		for {
			select {
			case pkt := <-dataQueue:
				pkt.Release()
			default:
				return
			}
		}
	}()
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for elem := range openQueue {
				if data, _ := elem.msg.conn.handleInboundMessage(elem.msg); data != nil {
					elem.opened = data
				}
				elem.Unlock()
			}
		}()
	}
	go func() {
		elem := newReadQueueElem(conn)
		var timer *time.Timer
		defer func() {
			if timer != nil {
				timer.Stop()
			}
			close(deliveryQueue)
			close(openQueue)
			if elem != nil {
				elem.Release()
			}
		}()
		var backoff netutils.Backoff
		for {
			if err := elem.msg.Read(); err != nil {
				select {
				case <-conn.done:
					return
				default:
				}
				if delay, ok := backoff.ErrBackoff(err); ok {
					if timer == nil {
						timer = time.NewTimer(delay)
					} else {
						timer.Reset(delay)
					}
					select {
					case <-timer.C:
					case <-conn.done:
						return
					}
					continue
				}
				conn.closeWithReadError(err)
				return
			}
			backoff.Reset()

			elem.Lock()
			select {
			case deliveryQueue <- elem:
				select {
				case openQueue <- elem:
					elem = newReadQueueElem(conn)
				case <-conn.done:
					// Delivery owns the element, but no decrypt worker received it.
					elem.Unlock()
					elem = nil
					return
				}
			case <-conn.done:
				elem.Unlock()
				return
			default:
				elem.Unlock()
			}
		}
	}()
	return dataQueue
}

type writeQueueElem struct {
	sync.Mutex
	sealed []byte
	addr   netip.AddrPort

	buf  *bufpool.Buffer
	peer *peerWriter
}

var writeQueueElemPool = sync.Pool{
	New: func() interface{} {
		return new(writeQueueElem)
	},
}

func newWriteQueueElem(chunks [][]byte, peer *peer) *writeQueueElem {
	elem := writeQueueElemPool.Get().(*writeQueueElem)

	buf := bufpool.Get()
	elem.buf = buf

	m := header.TransportDataMessage(buf.Bytes())
	n := 0
	for _, chunk := range chunks {
		n += copy(m.Packet()[n:], chunk)
	}

	elem.peer = &peerWriter{
		data:  m.Packet()[:n],
		peer:  peer,
		start: time.Now(),
	}
	return elem
}

func (elem *writeQueueElem) Release() {
	bufpool.Put(elem.buf)
	elem.sealed = nil
	elem.addr = netip.AddrPort{}
	elem.buf = nil
	elem.peer = nil
	writeQueueElemPool.Put(elem)
}

type writeQueue struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	closed    chan struct{}

	sealQueue chan *writeQueueElem
}

type sendQueue struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	done      chan struct{}
	*writeQueue
	deliveryQueue chan *writeQueueElem
}

func (wq *writeQueue) newSendQueue(size int) *sendQueue {
	sq := &sendQueue{
		writeQueue:    wq,
		done:          make(chan struct{}),
		deliveryQueue: make(chan *writeQueueElem, size),
	}
	go func() {
		for elem := range sq.deliveryQueue {
			elem.Lock()
			//lint:ignore SA2001 Lock to wait for encryption.
			elem.Unlock()
			select {
			case <-sq.done:
			case <-sq.closed:
			default:
				if elem.sealed != nil {
					elem.peer.send(elem.sealed, elem.addr)
				}
			}
			elem.Release()
		}
	}()
	return sq
}

func (sq *sendQueue) Close() {
	sq.closeOnce.Do(func() {
		close(sq.done)
		sq.mu.Lock()
		defer sq.mu.Unlock()
		close(sq.deliveryQueue)
	})
}

func (sq *sendQueue) enqueueChunks(chunks [][]byte, peer *peer) (int, error) {
	sq.mu.RLock()
	defer sq.mu.RUnlock()
	select {
	case <-sq.done:
		return 0, net.ErrClosed
	default:
	}
	sq.writeQueue.mu.RLock()
	defer sq.writeQueue.mu.RUnlock()
	select {
	case <-sq.done:
		return 0, net.ErrClosed
	case <-sq.closed:
		return 0, net.ErrClosed
	default:
	}

	if peer.IsBlocked() {
		return 0, ErrPeerBlocked
	}
	remaining := MaximumDataSize
	for _, chunk := range chunks {
		if len(chunk) > remaining {
			return 0, ErrMessageTooLarge
		}
		remaining -= len(chunk)
	}
	elem := newWriteQueueElem(chunks, peer)
	elem.Lock()
	// Read the length before the element is transferred to the queue.
	n := len(elem.peer.data)
	select {
	case sq.deliveryQueue <- elem:
		select {
		case sq.sealQueue <- elem:
			return n, nil
		case <-sq.done:
			elem.Unlock()
			return 0, net.ErrClosed
		case <-sq.closed:
			// The delivery worker owns the queued buffer and releases it.
			elem.Unlock()
			return 0, net.ErrClosed
		}
	case <-sq.done:
		elem.Unlock()
		elem.Release()
		return 0, net.ErrClosed
	case <-sq.closed:
		elem.Unlock()
		elem.Release()
		return 0, net.ErrClosed
	}
}

func newWriteQueue(size int) *writeQueue {
	wq := &writeQueue{
		closed:    make(chan struct{}),
		sealQueue: make(chan *writeQueueElem, size),
	}
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for elem := range wq.sealQueue {
				if b, addr, err := elem.peer.seal(elem.buf.Bytes()); err == nil {
					elem.sealed = b
					elem.addr = addr
				} else {
					elem.peer.logV(3).Printf("Failed to seal: %v", err)
				}
				elem.Unlock()
			}
		}()
	}
	return wq
}

func (wq *writeQueue) Close() {
	wq.closeOnce.Do(func() {
		close(wq.closed)
		wq.mu.Lock()
		defer wq.mu.Unlock()
		close(wq.sealQueue)
	})
}
