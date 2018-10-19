package endpoint

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/lucas-clemente/quic-go"
	"go.uber.org/zap"
)

// A QuicConfig structure is used to configure a QUIC endpoint.
type quicConfig struct {
	config
	TLS  tls.Config
	Quic quic.Config
}

type QuicOption interface {
	Option

	ApplyQuicConfig(*quicConfig)
}

type QuicOptionFunc func(*quicConfig)

var _ QuicOption = QuicOptionFunc(nil)

func (fn QuicOptionFunc) ApplyConfig(config *config) {
	panic(fn)
}

func (fn QuicOptionFunc) ApplyQuicConfig(config *quicConfig) {
	fn(config)
}

func newQuicConfig(options []Option) *quicConfig {
	config := new(quicConfig)

	for _, option := range options {
		switch opt := option.(type) {
		case Option:
			opt.ApplyConfig(&config.config)
		case QuicOption:
			opt.ApplyQuicConfig(config)
		default:
			panic(option)
		}
	}

	return config
}

// QuicEndpoint accepts incoming connections on the endopint with QUIC protocol.
type QuicEndpoint struct {
	*quicConfig
	quic.Listener
}

var _ Endpoint = (*QuicEndpoint)(nil)

// NewQuicEndpoint creates a new QuicEndpoint.
func NewQuicEndpoint(address string, options ...Option) (endpoint *QuicEndpoint, err error) {
	var conn net.PacketConn

	conn, err = net.ListenPacket("udp", address)

	if err != nil {
		return
	}

	config := newQuicConfig(options)
	config.Logger = config.Logger.Named("quic")

	listener, err := quic.Listen(conn, &config.TLS, &config.Quic)

	if err != nil {
		return
	}

	config.Info("endpoint is listening", zap.Stringer("addr", listener.Addr()))

	endpoint = &QuicEndpoint{config, listener}

	return
}

// Name returns the name of the endpoint.
func (endpoint *QuicEndpoint) Name() string {
	return "quic"
}

// Serve accepts incoming connections on the endopint, creating a new session for each.
func (endpoint *QuicEndpoint) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := make(chan quic.Session)

	go func() error {
		defer cancel()
		defer close(c)

		for {
			session, err := endpoint.Accept()

			if err != nil {
				endpoint.Error("fail to accept connection", zap.Error(err))

				return err
			}

			endpoint.Info("accepted session",
				zap.Stringer("peer", session.RemoteAddr()),
				zap.Stringer("local", session.LocalAddr()))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case c <- session:
				break
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case session := <-c:
			if session == nil {
				break
			}
		}
	}

	return nil
}
