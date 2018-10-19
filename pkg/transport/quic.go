package transport

import (
	"github.com/lucas-clemente/quic-go"
)

type QuicTransport struct {
	session quic.Session
}

var _ Transport = (*QuicTransport)(nil)
