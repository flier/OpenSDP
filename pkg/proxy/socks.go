package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"go.uber.org/zap"
)

const (
	userPassAuthVersion = 1
	authSuccess         = 0
	authFailure         = 1
)

var (
	ErrUnsupportVersion     = errors.New("unsupport socks version")
	ErrNoSupportedAuth      = errors.New("No supported authentication mechanism")
	ErrUserAuthFailed       = errors.New("User authentication failed")
	ErrUnrecognizedAddrType = errors.New("Unrecognized address type")
)

type socksVersion byte

const (
	socks4Version socksVersion = 4
	socks5Version socksVersion = 5
)

type socksCommand byte

const (
	tcpConnect   socksCommand = 1
	tcpBind      socksCommand = 2
	udpAssociate socksCommand = 3
)

type socksAddrType byte

const (
	ipv4Address socksAddrType = 1
	fqdnAddress socksAddrType = 3
	ipv6Address socksAddrType = 4
)

type socks4Status byte

const (
	v4RequestGranted socks4Status = 0x5A
	requestRejected  socks4Status = 0x5B // request rejected or failed
	noIdentd         socks4Status = 0x5C // request failed because client is not running identd (or not reachable from the server)
	identdRejected   socks4Status = 0x5D // request failed because client's identd could not confirm the user ID string in the request
)

type socks5Status byte

const (
	requestGranted          socks5Status = iota // request granted
	generalFailure                              // general failure
	connectionNotAllowed                        // connection not allowed by ruleset
	networkUnreachable                          // network unreachable
	hostUnreachable                             // host unreachable
	connectionRefused                           // connection refused by destination host
	ttlExpired                                  // TTL expired
	commandNotSupported                         // command not supported / protocol error
	addressTypeNotSupported                     // address type not supported
)

type AuthMethod byte

const (
	NoAuth AuthMethod = iota
	GSSAP
	UserPass
	NoAcceptable AuthMethod = 0xFF
)

type AuthContext interface{}

type Authenticator interface {
	Method() AuthMethod

	Authenticate(reader io.Reader, writer io.Writer) (AuthContext, error)
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) Method() AuthMethod {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (AuthContext, error) {
	_, err := writer.Write([]byte{byte(socks5Version), byte(NoAuth)})

	return nil, err
}

type CredentialStore interface {
	Verify(user, password string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]

	return ok && password == pass
}

// UserPassAuthenticator is used to handle username/password based authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) Method() AuthMethod {
	return UserPass
}

func (a UserPassAuthenticator) Authenticate(r io.Reader, w io.Writer) (ctx AuthContext, err error) {
	// Tell the client to use user/pass auth
	_, err = w.Write([]byte{byte(socks5Version), byte(UserPass)})

	if err != nil {
		return
	}

	// Get the version and username length
	buf := []byte{0, 0}

	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}

	// Ensure we are compatible
	if buf[0] != userPassAuthVersion {
		err = fmt.Errorf("Unsupported auth version: %v", buf[0])
		return
	}

	// Get the user name
	username := make([]byte, int(buf[1]))

	if _, err = io.ReadFull(r, username); err != nil {
		return
	}

	// Get the password length
	if _, err = io.ReadFull(r, buf[:1]); err != nil {
		return
	}

	// Get the password
	password := make([]byte, int(buf[0]))

	if _, err = io.ReadFull(r, password); err != nil {
		return
	}

	// Verify the password
	if a.Credentials.Verify(string(username), string(password)) {
		if _, err = w.Write([]byte{userPassAuthVersion, authSuccess}); err != nil {
			return
		}
	} else {
		if _, err = w.Write([]byte{userPassAuthVersion, authFailure}); err != nil {
			return
		}

		return nil, ErrUserAuthFailed
	}

	return username, nil
}

type SocksOption func(*SocksConfig)

func WithLogger(logger *zap.Logger) SocksOption {
	return func(config *SocksConfig) {
		config.Logger = logger
	}
}

func WithAuthenticator(auth Authenticator) SocksOption {
	return func(config *SocksConfig) {
		config.Authenticators[auth.Method()] = auth
	}
}

type SocksConfig struct {
	*zap.Logger
	Resolver       *net.Resolver
	Authenticators map[AuthMethod]Authenticator
}

func newSocksConfig(options []SocksOption) *SocksConfig {
	config := &SocksConfig{
		zap.NewNop(),
		net.DefaultResolver,
		make(map[AuthMethod]Authenticator),
	}
	config.Authenticators[NoAuth] = NoAuthAuthenticator{}

	for _, option := range options {
		option(config)
	}

	return config
}

type SocksRequest struct {
	version      socksVersion
	cmd          socksCommand
	ip           net.IP
	port         uint16
	user, domain string
}

type SocksServer struct {
	*SocksConfig
	*net.TCPListener
}

func NewSocksServer(address string, options ...SocksOption) (*SocksServer, error) {
	cfg := newSocksConfig(options)

	addr, err := net.ResolveTCPAddr("tcp", address)

	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp", addr)

	if err != nil {
		return nil, err
	}

	return &SocksServer{cfg, listener}, nil
}

func (s *SocksServer) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c := make(chan *net.TCPConn)

	go func() error {
		defer cancel()
		defer close(c)

		for {
			conn, err := s.AcceptTCP()

			if err != nil {
				if ctx.Err() == nil {
					s.Error("fail to accept connection", zap.Error(err))
				}

				return err
			}

			s.Info("accepted connection",
				zap.Stringer("peer", conn.RemoteAddr()),
				zap.Stringer("local", conn.LocalAddr()))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case c <- conn:
				break
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case conn := <-c:
			if conn == nil {
				break
			}

			go s.serveConn(ctx, conn)
		}
	}

	return nil
}

func (s *SocksServer) serveConn(ctx context.Context, conn *net.TCPConn) (err error) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	var version byte

	if version, err = r.ReadByte(); err != nil {
		return
	}

	var req *SocksRequest

	switch socksVersion(version) {
	case socks4Version:
		if req, err = s.readSocks4Request(ctx, r); err != nil {
			return
		}

	case socks5Version:
		var cred AuthContext

		if cred, err = s.authenticate(r, w); err != nil {
			return
		}

		if err = w.Flush(); err != nil {
			return
		}

		if req, err = s.readSocks5Request(ctx, r); err != nil {
			return
		}

		req.user, _ = cred.(string)
	default:
		return ErrUnsupportVersion
	}

	return s.handleRequest(ctx, conn, req)
}

func (s *SocksServer) authenticate(r *bufio.Reader, w *bufio.Writer) (cred AuthContext, err error) {
	var n byte

	n, err = r.ReadByte()

	if err != nil {
		return
	}

	var method byte
	var methods []AuthMethod

	for i := 0; i < int(n); i++ {
		method, err = r.ReadByte()

		if err != nil {
			return
		}

		methods = append(methods, AuthMethod(method))
	}

	for _, method := range methods {
		if authenticator, found := s.Authenticators[method]; found {
			return authenticator.Authenticate(r, w)
		}
	}

	_, err = w.Write([]byte{byte(socks5Version), byte(NoAcceptable)})

	if err != nil {
		return
	}

	return nil, ErrNoSupportedAuth
}

func (s *SocksServer) readSocks4Request(ctx context.Context, r *bufio.Reader) (req *SocksRequest, err error) {
	buf := make([]byte, 7)

	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}

	cmd := socksCommand(buf[0])
	port := binary.BigEndian.Uint16(buf[1:3])

	if buf, err = r.ReadSlice(0); err != nil {
		return
	}

	user := string(buf)
	ip := net.IP(buf[3:7])

	var domain string

	if ip[0] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] != 0 {
		if buf, err = r.ReadSlice(0); err != nil {
			return
		}

		ip = nil
		domain = string(buf)
	}

	return &SocksRequest{
		socks4Version,
		cmd,
		ip,
		port,
		user,
		domain,
	}, nil
}

func (s *SocksServer) readSocks5Request(ctx context.Context, r *bufio.Reader) (req *SocksRequest, err error) {
	var ip net.IP
	var domain string

	buf := make([]byte, 7)

	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}

	cmd := socksCommand(buf[0])
	addrType := socksAddrType(buf[2])

	switch addrType {
	case ipv4Address:
		ip := make([]byte, net.IPv4len)

		if _, err = io.ReadFull(r, ip); err != nil {
			return
		}

	case ipv6Address:
		ip := make([]byte, net.IPv6len)

		if _, err = io.ReadFull(r, ip); err != nil {
			return
		}

	case fqdnAddress:
		var n byte

		if n, err = r.ReadByte(); err != nil {
			return
		}

		buf = make([]byte, n)

		if _, err = io.ReadFull(r, buf); err != nil {
			return
		}

		domain = string(buf)
	default:
		err = ErrUnrecognizedAddrType
		return
	}

	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return
	}

	port := binary.BigEndian.Uint16(buf[:2])

	return &SocksRequest{
		socks5Version,
		cmd,
		ip,
		port,
		"",
		domain,
	}, nil
}

func (s *SocksServer) handleRequest(ctx context.Context, conn *net.TCPConn, req *SocksRequest) (err error) {
	switch req.cmd {
	case tcpConnect:
		return s.handleTcpConnect(ctx, conn, req)
	case tcpBind:
		return s.handleTcpBind(ctx, conn, req)
	case udpAssociate:
		return s.handleUdpAssociate(ctx, conn, req)
	}

	return
}

func (s *SocksServer) handleTcpConnect(ctx context.Context, conn *net.TCPConn, req *SocksRequest) (err error) {
	return
}

func (s *SocksServer) handleTcpBind(ctx context.Context, conn *net.TCPConn, req *SocksRequest) (err error) {
	return
}

func (s *SocksServer) handleUdpAssociate(ctx context.Context, conn *net.TCPConn, req *SocksRequest) (err error) {
	return
}
