package main

import (
	"context"
	"strings"
)

// StartupConfig defines the set of input command line options
// for a user to provide to the app on startup
type StartupConfig struct {
	PrintConfig bool
	ConfigFile  string
	DryRun      bool
}

// AppConfig defines the set of options loaded from the configuration
// file passed via StartupConfig.ConfgiFile
type AppConfig struct {
	Greeting   string     `yaml:"greeting"`
	Scheme     string     `yaml:"http_listen_scheme"`
	Port       int        `yaml:"http_listen_port"`
	TlsConfig  TlsConfig  `yaml:"http_tls_config,omitempty"`
	AuthConfig AuthConfig `yaml:"auth_config,omitempty"`
}

// TlsConfig defines the TLS options that may be specified
// as part of an AppConfig
type TlsConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AuthConfig defines the Authorization options that may be
// specified as part of an AppConfig
type AuthConfig struct {
	AuthType         string           `yaml:"type"`
	BasicAuthConfig  BasicAuthConfig  `yaml:"basic_auth_config,omitempty"`
	BearerAuthConfig BearerAuthConfig `yaml:"bearer_auth_config,omitempty"`
}

// BasicAuthConfig defines the authorization options used for basic authorization
type BasicAuthConfig struct {
	Token string `yaml:"token"`
}

// BearerAuthConfig defines the authorization options used for bearer authorization
type BearerAuthConfig struct {
	Domain   string `yaml:"domain"`
	Audience string `yaml:"audience"`
}

// CustomClaims contains custom data we want from the token
type CustomClaims struct {
	Scope string `json:"scope"`
}

// Validate does nothing for this example, but we need it to satisfy
// the validator.CustomClaims interface
func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

func (c CustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}
