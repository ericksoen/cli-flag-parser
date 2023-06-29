package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/go-yaml/yaml"
)

var startupConfig StartupConfig
var appConfig AppConfig

func EnsureValidBasicToken(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// TODO: Move this into an error handler similar to what the Auth0 jwt.ErrorHandler does
		if authHeader == "" {
			http.Error(w, "Authorization failed", 403)
			return
		}

		headerTokens := strings.Split(authHeader, " ")

		if len(headerTokens) != 2 {
			http.Error(w, "Authorization failed", 403)
			return
		}

		if headerTokens[1] != appConfig.AuthConfig.BasicAuthConfig.Token {
			http.Error(w, "Authorization failed", 403)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func EnsureValidBearerToken() func(next http.Handler) http.Handler {

	issuerURL, err := url.Parse("https://" + appConfig.AuthConfig.BearerAuthConfig.Domain + "/")

	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{appConfig.AuthConfig.BearerAuthConfig.Audience},
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &CustomClaims{}
			},
		),
		validator.WithAllowedClockSkew(time.Minute),
	)

	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Encountered error while validating JWT: %v", err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Failed to validate JWT.}`))
	}

	middleware := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
	)

	return func(next http.Handler) http.Handler {
		return middleware.CheckJWT(next)
	}
}

func greeter(w http.ResponseWriter, req *http.Request) {

	greeting := fmt.Sprintf("%s world!\n", appConfig.Greeting)

	fmt.Fprintf(w, greeting)
}

func (c *StartupConfig) Register(f *flag.FlagSet) {
	f.StringVar(&startupConfig.ConfigFile, "config.file", "", "YAML file to load")
	f.BoolVar(&startupConfig.PrintConfig, "config.print", false, "Write the config to stdout")
	f.BoolVar(&startupConfig.DryRun, "config.dry-run", false, "Run in dry-run mode")
}
func main() {

	args := os.Args[1:]

	fs := flag.NewFlagSet("Command line arguments", flag.ExitOnError)
	startupConfig.Register(fs)

	err := fs.Parse(args)
	if err != nil {
		log.Fatalf("Failed to parse command line arguments due to error = %s", err.Error())
	}

	log.Printf("The input config file argument = %s\n", startupConfig.ConfigFile)

	if startupConfig.ConfigFile == "" {
		log.Fatalf("-config.file is required and was not provided.")
	}

	if _, err := os.Stat(startupConfig.ConfigFile); err != nil {
		log.Fatalf("File at location = %s does not exist.", startupConfig.ConfigFile)
	}

	data, err := ioutil.ReadFile(*&startupConfig.ConfigFile)

	if err != nil {
		log.Fatalf("Failed to read file with error = %s", err)
	}

	err = yaml.Unmarshal(data, &appConfig)

	if err != nil {
		log.Fatalf("Failed to unmarshal type with error = %s", err)
	}

	if startupConfig.PrintConfig {
		log.Printf("---\n# Config\n# v1.0.0\n%s\n---\n", string(data))
	}

	router := http.NewServeMux()
	if appConfig.AuthConfig == (AuthConfig{}) {
		log.Printf("Starting application without authorization")
		router.Handle("/greeter", http.HandlerFunc(greeter))
	} else {

		permittedAuthTypes := map[string]bool{"bearer": true, "basic": true}

		if ok := permittedAuthTypes[strings.ToLower(appConfig.AuthConfig.AuthType)]; !ok {
			log.Fatalf("Received auth type = %s. Only `basic` and `bearer` are supported at this time.", appConfig.AuthConfig.AuthType)
		}

		log.Printf("Application will run using %s authorization", appConfig.AuthConfig.AuthType)

		switch strings.ToLower(appConfig.AuthConfig.AuthType) {
		case "bearer":
			router.Handle("/greeter", EnsureValidBearerToken()(
				http.HandlerFunc(greeter),
			))
			break
		case "basic":
			router.Handle("/greeter", EnsureValidBasicToken(http.HandlerFunc(greeter)))
		}

	}

	log.Printf("Using scheme = %s with port = %d", appConfig.Scheme, appConfig.Port)

	if startupConfig.DryRun {
		log.Printf("Starting application in dry-run.")
		log.Printf("Exiting...")
		os.Exit(0)
	}
	port := fmt.Sprintf(":%d", appConfig.Port)

	switch appConfig.Scheme {
	case "http":
		err := http.ListenAndServe(port, router)

		if err != nil {
			log.Fatalf("Listen and serve: %s", err)
		}

		break
	case "https":
		err := http.ListenAndServeTLS(
			port,
			appConfig.TlsConfig.CertFile,
			appConfig.TlsConfig.KeyFile,
			router,
		)

		if err != nil {
			log.Fatalf("Listen and serve: %s", err)
		}
		break
	}
}
