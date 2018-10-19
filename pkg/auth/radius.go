package auth

import (
	"layeh.com/radius"
)

// RadiusProvider provides authentication service with RADIUS server
type RadiusProvider struct {
	client *radius.Client
}

var _ Provider = (*RadiusProvider)(nil)
