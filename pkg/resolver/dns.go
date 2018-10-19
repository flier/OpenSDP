package resolver

type DnsResolver struct {
	c *dns.Client
}

var _ Resolver = (*DnsResolver)(nil)