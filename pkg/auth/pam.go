package auth

import (
	"github.com/msteinert/pam"
)

// PamProvider provides authentication service with PAM API
type PamProvider struct {
	transport *pam.Transaction
}

var _ Provider = (*PamProvider)(nil)
