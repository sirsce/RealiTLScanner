module github.com/myusername/RealiTLScanner

go 1.21

require github.com/oschwald/geoip2-golang v1.9.0

require (
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

// Personal fork of XTLS/RealiTLScanner for learning and experimentation.
// Upstream: https://github.com/XTLS/RealiTLScanner
//
// Notes:
// - Bumped golang.org/x/sys to v0.17.0 for latest security patches
// - TODO: explore adding IPv6 scanning support
