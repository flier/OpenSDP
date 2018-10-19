package auth

import (
	"gopkg.in/ldap.v2"
)

// LdapProvider provides authentication service with LDAP server
type LdapProvider struct {
	conn *ldap.Conn
}

var _ Provider = (*LdapProvider)(nil)
