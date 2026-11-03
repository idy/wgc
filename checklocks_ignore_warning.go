package wireguard

func CheckLocksIgnoreWarning() {
	_ = errConnClosed
}

func (s *secureSession) CheckLocksIgnoreWarning() {
	_ = s.peer
	_ = s.sender
	_ = s.isInitiator
}

func (p *peer) CheckLocksIgnoreWarning() {
	_ = p.mac1GenerateKey
}

func (conn *Conn) CheckLocksIgnoreWarning() {
	_ = conn.peerConfigLookup
}
