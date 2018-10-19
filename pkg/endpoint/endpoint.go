package endpoint

import (
	"context"
	"errors"
	"io"
	"net/url"

	"go.uber.org/zap"
)

var ErrUnknownScheme = errors.New("unknown scheme")

type Option interface {
	ApplyConfig(*config)
}

type OptionFunc func(*config)

func (fn OptionFunc) ApplyConfig(config *config) {
	fn(config)
}

// WithLogger configures the logger
func WithLogger(logger *zap.Logger) OptionFunc {
	return func(cfg *config) {
		cfg.Logger = logger
	}
}

type Config interface{}

type config struct {
	*zap.Logger
}

type Endpoint interface {
	io.Closer

	// Name returns the name of the endpoint.
	Name() string

	// Serve accepts incoming connections on the endopint, creating a new session for each.
	Serve(ctx context.Context) error
}

func ForURI(uri *url.URL, options ...Option) (endpoint Endpoint, err error) {
	switch uri.Scheme {
	case "quic":
		return NewQuicEndpoint(uri.Host, options...)
	}

	return nil, ErrUnknownScheme
}
