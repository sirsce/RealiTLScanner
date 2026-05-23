package main

import (
	"github.com/oschwald/geoip2-golang"
	"log/slog"
	"net"
	"sync"
)

type Geo struct {
	geoReader *geoip2.Reader
	mu        sync.Mutex
}

func NewGeo() *Geo {
	geo := &Geo{
		mu: sync.Mutex{},
	}
	reader, err := geoip2.Open("Country.mmdb")
	if err != nil {
		// GeoIP is optional; scanner will still work without it
		slog.Warn("Cannot open Country.mmdb, GeoIP lookup disabled")
		return geo
	}
	slog.Info("Enabled GeoIP")
	geo.geoReader = reader
	return geo
}

func (o *Geo) GetGeo(ip net.IP) string {
	if o.geoReader == nil {
		return "N/A"
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	country, err := o.geoReader.Country(ip)
	if err != nil {
		slog.Debug("Error reading geo", "err", err)
		return "N/A"
	}
	// Fall back to registered country if the IP-level country is not set
	if country.Country.IsoCode == "" {
		return country.RegisteredCountry.IsoCode
	}
	return country.Country.IsoCode
}
