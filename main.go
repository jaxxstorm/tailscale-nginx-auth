package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

var Version = "dev"

type CLI struct {
	Debug bool `help:"Print debug logs" default:"false" env:"TS_NGINX_AUTH_DEBUG"`
	Version bool `help:"Print version and exit" default:"false" env:"TS_NGINX_AUTH_SHOW_VERSION"`

	ClientID     string `help:"Tailscale OAuth client ID" env:"TS_NGINX_AUTH_CLIENT_ID"`
	ClientSecret string `help:"Tailscale OAuth client secret" env:"TS_NGINX_AUTH_CLIENT_SECRET"`

	Tags string `help:"Comma-separated tags for ephemeral keys" default:"tag:nginx-auth" env:"TS_NGINX_AUTH_TAGS"`

	Ephemeral bool   `help:"Use ephemeral Tailscale node (no stored identity)" default:"true" env:"TS_NGINX_AUTH_EPHEMERAL"`
	Hostname  string `help:"Tailscale node hostname" default:"tsnet-nginx-auth" env:"TS_NGINX_AUTH_HOSTNAME"`

	StateDir string `help:"Directory to store Tailscale node state if ephemeral=false" default:"./nginx-auth-ts-state" env:"TS_NGINX_AUTH_STATE_DIR"`

	Port int `help:"Port to listen on (on cluster network)" default:"8080" env:"TS_NGINX_AUTH_PORT"`
}

func main() {
	var cli CLI
	kong.Parse(&cli,
		kong.Name("tailscale-nginx-auth"),
		kong.Description("A Tailscale-embedded auth service for NGINX external authentication."),
	)

	// If --version is set, print version and exit
	if cli.Version {
		fmt.Println("Version:", Version)
		return
	}

	// Otherwise, run the main server logic
	if err := runServer(&cli); err != nil {
		log.Fatalf("tailscale-nginx-auth error: %v", err)
	}
}

func runServer(cli *CLI) error {
	var logger *zap.Logger
	var err error
	if cli.Debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer logger.Sync()

	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	log.SetFlags(0)
	log.SetOutput(zapWriter{logger.With(zap.String("component", "stdlog"))})

	if cli.Debug {
		logger.Info("Debug mode enabled")
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	logger.Info("Starting nginx-auth",
		zap.String("hostname", cli.Hostname),
		zap.Bool("ephemeral", cli.Ephemeral),
		zap.Int("port", cli.Port),
	)

	tsServer := &tsnet.Server{
		Hostname:  cli.Hostname,
		Ephemeral: cli.Ephemeral,
		Logf: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(format, args...),
				zap.String("component", "tsnet.logf"))
		},
		UserLogf: func(format string, args ...interface{}) {
			logger.Info(fmt.Sprintf(format, args...),
				zap.String("component", "tsnet.userlogf"))
		},
	}
	if !cli.Ephemeral {
		tsServer.Dir = cli.StateDir
	}

	if err := tsServer.Start(); err != nil {
		logger.Fatal("tsnet server failed to start", zap.Error(err))
	}
	defer tsServer.Close()

	// Use LocalClient to call WhoIs() for Tailscale ACL checks.
	lc, err := tsServer.LocalClient()
	if err != nil {
		logger.Fatal("Could not get LocalClient from tsnet server", zap.Error(err))
	}

	// login logic
	var adminClient *tailscale.Client
	oidcEnabled := (cli.ClientID != "" && cli.ClientSecret != "")
	if oidcEnabled {
		logger.Info("Using Tailscale OAuth2 client to create ephemeral auth keys if needed",
			zap.String("client_id", cli.ClientID))

		creds := clientcredentials.Config{
			ClientID:     cli.ClientID,
			ClientSecret: cli.ClientSecret,
			TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
		}
		adminClient = tailscale.NewClient("-", nil)
		adminClient.HTTPClient = creds.Client(context.Background())

		// Wait for node to need login, then generate ephemeral key
		if err := waitForRunningOrLogin(lc, adminClient, cli.Tags, logger); err != nil {
			logger.Fatal("Error while waiting for Tailscale node to come online", zap.Error(err))
		}
	} else {
		logger.Info("No OAuth2 client ID/secret provided; if Tailscale needs login, check logs for the login URL.")
	}

	router := gin.New()
	router.Use(gin.Recovery())

	router.Use(func(c *gin.Context) {
		nginxAuthMiddleware(c, lc, logger)
	})

	// Basic health endpoint
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Any("/", func(c *gin.Context) {
		c.Status(http.StatusNoContent) // 204 means authorized
	})

	// We don't listen on the TS address because we need to be accessible in cluster
	listenAddr := fmt.Sprintf("0.0.0.0:%d", cli.Port)
	logger.Info("Listening on local interface", zap.String("addr", listenAddr))

	if err := http.ListenAndServe(listenAddr, router); err != nil {
		logger.Fatal("HTTP server crashed", zap.Error(err))
	}
	return nil
}

// waitForRunningOrLogin checks the Tailscale node’s status, creating ephemeral auth keys if "NeedsLogin".
func waitForRunningOrLogin(lc *tailscale.LocalClient, adminClient *tailscale.Client, tags string, logger *zap.Logger) error {
	ctx := context.Background()
	loginDone := false
	machineAuthShown := false

	for {
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("error getting Tailscale status: %w", err)
		}
		switch st.BackendState {
		case "Running":
			return nil
		case "NeedsLogin":
			if loginDone {
				time.Sleep(time.Second)
				continue
			}
			logger.Info("Tailscale is in NeedsLogin -> creating ephemeral auth key via Admin API")

			keyCaps := tailscale.KeyCapabilities{
				Devices: tailscale.KeyDeviceCapabilities{
					Create: tailscale.KeyDeviceCreateCapabilities{
						Reusable:      false,
						Preauthorized: true,
						Tags:          strings.Split(tags, ","),
					},
				},
			}
			authKey, _, err := adminClient.CreateKey(ctx, keyCaps)
			if err != nil {
				return fmt.Errorf("failed creating ephemeral auth key: %w", err)
			}
			if err := lc.Start(ctx, ipn.Options{AuthKey: authKey}); err != nil {
				return fmt.Errorf("failed to Start Tailscale with ephemeral key: %w", err)
			}
			if err := lc.StartLoginInteractive(ctx); err != nil {
				return fmt.Errorf("failed StartLoginInteractive: %w", err)
			}
			loginDone = true

		case "NeedsMachineAuth":
			if !machineAuthShown {
				logger.Info("Machine approval required; visit the Tailscale admin panel to approve.")
				machineAuthShown = true
			}
		default:
			// Keep waiting
		}
		time.Sleep(time.Second)
	}
}

// nginxAuthMiddleware does the "lbrlabs.com/cap/nginx-auth" check for `routes` (methods, hosts, paths).
func nginxAuthMiddleware(c *gin.Context, lc *tailscale.LocalClient, logger *zap.Logger) {

	// check the X-Forwarded-For header
	// if not present, fall back to the RemoteAddr
	ip := c.Request.Header.Get("X-Forwarded-For")
	logger.Info("X-Forwarded-For header", zap.String("header", ip))
	if ip == "" {
		// fallback to parse IP from RemoteAddr
		ip, _, _ = net.SplitHostPort(c.Request.RemoteAddr)
	}

	st, err := lc.WhoIs(context.Background(), ip)
	if err != nil {
		logger.Warn("WhoIs lookup failed", zap.String("ip", ip), zap.Error(err))
		abortWithJSON(c, http.StatusUnauthorized, "permission denied, whois lookup failed")
		return
	}

	userLoginName := ""
	if st.UserProfile != nil {
		userLoginName = st.UserProfile.LoginName
	}

	logger.Info("Incoming request",
		zap.String("ip", ip),
		zap.String("method", c.Request.Method),
		zap.String("host", c.Request.Host),
		zap.String("path", c.Request.URL.Path),
		zap.String("user", userLoginName),
	)

	rawCap, ok := st.CapMap["lbrlabs.com/cap/nginx-auth"]
	if !ok {
		logger.Warn("Missing lbrlabs.com/cap/nginx-auth capability",
			zap.String("ip", ip),
			zap.String("user", userLoginName))
		abortWithJSON(c, http.StatusUnauthorized,
			"permission denied, missing nginx-auth capability")
		return
	}

	capBytes, err := json.Marshal(rawCap)
	if err != nil {
		logger.Warn("Failed to marshal raw capability data", zap.Error(err))
		abortWithJSON(c, http.StatusUnauthorized, "permission denied, bad capability data")
		return
	}

	var appCaps NginxAuthAppCapabilities
	if err := json.Unmarshal(capBytes, &appCaps); err != nil {
		logger.Warn("Failed to unmarshal capabilities JSON", zap.Error(err))
		abortWithJSON(c, http.StatusUnauthorized, "permission denied, capabilities parse error")
		return
	}

	hostNoPort := c.Request.Host
	if h, _, splitErr := net.SplitHostPort(hostNoPort); splitErr == nil && h != "" {
		hostNoPort = h
	}

	method := c.Request.Method
	path := c.Request.URL.Path

	allowed := false
	for _, subcapMap := range appCaps {
		if routesCap, haveRoutes := subcapMap["routes"]; haveRoutes {
			methodOK := matchStringListOrWildcard(method, routesCap.Methods)
			hostOK := matchHostWildcard(hostNoPort, routesCap.Hosts)
			pathOK := matchPathWildcard(path, routesCap.Paths)

			if methodOK && hostOK && pathOK {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		logger.Warn("Not authorized by 'routes' sub-capability",
			zap.String("ip", ip),
			zap.String("user", userLoginName),
			zap.String("method", method),
			zap.String("host", hostNoPort),
			zap.String("path", path),
		)
		abortWithJSON(c, http.StatusForbidden, "permission denied, sub-cap does not allow this method/host/path")
		return
	}

	// Optionally pass user info upstream
	c.Writer.Header().Set("Tailscale-User", userLoginName)
	c.Next()
}

// NginxAuthRoutesCapability is the shape of the "routes" sub-cap: methods, hosts, paths.
type NginxAuthRoutesCapability struct {
	Methods []string `json:"methods"`
	Hosts   []string `json:"hosts"`
	Paths   []string `json:"paths"`
}

// NginxAuthAppCapabilities is an array of objects describing sub-caps
type NginxAuthAppCapabilities []map[string]NginxAuthRoutesCapability

func matchStringListOrWildcard(item string, list []string) bool {
	for _, s := range list {
		if s == "*" || s == item {
			return true
		}
	}
	return false
}

func matchHostWildcard(host string, list []string) bool {
	for _, pattern := range list {
		if pattern == "*" {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			trimmed := strings.TrimPrefix(pattern, "*.")
			if host == trimmed || strings.HasSuffix(host, "."+trimmed) {
				return true
			}
		} else {
			if host == pattern {
				return true
			}
		}
	}
	return false
}

func matchPathWildcard(path string, list []string) bool {
	for _, p := range list {
		if p == "*" || p == path {
			return true
		}
	}
	return false
}

func abortWithJSON(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

// zapWriter bridges standard library logs into zap
type zapWriter struct{ logger *zap.Logger }

func (z zapWriter) Write(p []byte) (n int, err error) {
	str := strings.TrimSpace(string(p))
	z.logger.Info(str)
	return len(p), nil
}
