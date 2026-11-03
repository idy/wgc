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
			dataQueue <- pkt
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
		defer func() {
			close(deliveryQueue)
			close(openQueue)

			// If msg is delivered, it will be put back to the pool by the
			// receiver. If code reaches here, it means the msg is not
			// delivered, so we need to put it back.
			elem.Release()
		}()
		var backoff netutils.Backoff
		for {
			if err := elem.msg.Read(); err != nil {
				conn.mu.RLock()
				closed := conn.closed
				conn.mu.RUnlock()
				if closed {
					return
				}
				if delay, ok := backoff.ErrBackoff(err); ok {
					time.Sleep(delay)
					continue
				}
				return
			}
			backoff.Reset()

			elem.Lock()
			select {
			case deliveryQueue <- elem:
				openQueue <- elem
				elem = newReadQueueElem(conn)
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
		nn := copy(m.Packet()[n:], chunk)
		n += nn
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
	mu       sync.RWMutex
	isClosed bool
	*writeQueue
	deliveryQueue chan *writeQueueElem
}

func (wq *writeQueue) newSendQueue(size int) *sendQueue {
	sq := &sendQueue{
		writeQueue:    wq,
		deliveryQueue: make(chan *writeQueueElem, size),
	}
	go func() {
		for elem := range sq.deliveryQueue {
			elem.Lock()
			//lint:ignore SA2001 Lock to wait for encryption.
			elem.Unlock()
			if elem.sealed != nil {
				elem.peer.send(elem.sealed, elem.addr)
			}
			elem.Release()
		}
	}()
	return sq
}

func (sq *sendQueue) Close() {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	if !sq.isClosed {
		sq.isClosed = true
		close(sq.deliveryQueue)
	}
}

func (sq *sendQueue) enqueueChunks(chunks [][]byte, peer *peer) (int, error) {
	sq.mu.RLock()
	defer sq.mu.RUnlock()
	if sq.isClosed {
		return 0, net.ErrClosed
	}
	sq.writeQueue.mu.RLock()
	defer sq.writeQueue.mu.RUnlock()
	select {
	case <-sq.closed:
		return 0, net.ErrClosed
	default:
	}

	if peer.IsBlocked() {
		return 0, ErrPeerBlocked
	}
	elem := newWriteQueueElem(chunks, peer)
	elem.Lock()
	// the length must be read before the elem is sent to the queue.
	n := len(elem.peer.data)
	select {
	case sq.deliveryQueue <- elem:
		select {
		case sq.sealQueue <- elem:
			return n, nil
		case <-sq.closed:
			// The delivery worker owns the queued buffer and releases it.
			elem.Unlock()
			return 0, net.ErrClosed
		}
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
