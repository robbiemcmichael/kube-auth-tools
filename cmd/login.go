package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/robbiemcmichael/kube-auth-tools/connector"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type LoginConfig struct {
	User         string `json:"user"`
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
	Issuer       string `json:"issuer"`
	RedirectURL  string `json:"redirect-url"`
	Scopes       string `json:"scopes"`
}

var loginConfig LoginConfig

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Fetch an OIDC token",
	RunE: func(cmd *cobra.Command, args []string) error {
		return executeLogin(&loginConfig)
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	// TODO:
	// - Ability to add CA cert for issuer
	// - Add --prompt option to prompt for username and ldapPassword
	// - Create localhost webserver to maintain proper OAuth2 flow
	// - Whoami command
	rootCmd.AddCommand(loginCmd)
	loginCmd.PersistentFlags().String("user", "", "name of the user in the kubeconfig file")
	loginCmd.PersistentFlags().String("issuer", "", "OpenID Connect issuer URL")
	loginCmd.PersistentFlags().String("client-id", "", "OAuth2 client ID")
	loginCmd.PersistentFlags().String("client-secret", "", "OAuth2 client secret")
	loginCmd.PersistentFlags().String("redirect-url", "http://127.0.0.1:5556/callback", "OAuth2 redirect URL")
	loginCmd.PersistentFlags().String("scopes", "profile,email,groups,offline_access", "OAuth2 scopes")
}

func initLogin() {
	// There's a horrible amount of repetition here, but it seems as though Cobra
	// and Viper do not provide a sensible way to load config from command line
	// flags, environment variables and a config file when they all use different
	// formats (--some-flag, SOME_FLAG and someFlag, respectively).

	viper.SetEnvPrefix("kubectl_plugins_local_flag")

	viper.BindEnv("user")
	viper.BindEnv("issuer")
	viper.BindEnv("client_id")
	viper.BindEnv("client_secret")
	viper.BindEnv("redirect_url")
	viper.BindEnv("scopes")

	viper.BindPFlag("user", loginCmd.PersistentFlags().Lookup("user"))
	viper.BindPFlag("issuer", loginCmd.PersistentFlags().Lookup("issuer"))
	viper.BindPFlag("client_id", loginCmd.PersistentFlags().Lookup("client-id"))
	viper.BindPFlag("client_secret", loginCmd.PersistentFlags().Lookup("client-secret"))
	viper.BindPFlag("redirect_url", loginCmd.PersistentFlags().Lookup("redirect-url"))
	viper.BindPFlag("scopes", loginCmd.PersistentFlags().Lookup("scopes"))

	loginConfig.User = viper.GetString("user")
	loginConfig.Issuer = viper.GetString("issuer")
	loginConfig.ClientID = viper.GetString("client_id")
	loginConfig.ClientSecret = viper.GetString("client_secret")
	loginConfig.RedirectURL = viper.GetString("redirect_url")
	loginConfig.Scopes = viper.GetString("scopes")
}

func checkLoginConfig(cfg *LoginConfig) error {
	if cfg.User == "" {
		return fmt.Errorf("--user must be specified")
	}

	if cfg.Issuer == "" {
		return fmt.Errorf("--issuer must be specified")
	}

	if cfg.ClientID == "" {
		return fmt.Errorf("--client-id must be specified")
	}

	if cfg.ClientSecret == "" {
		return fmt.Errorf("--client-secret must be specified")
	}

	if cfg.RedirectURL == "" {
		return fmt.Errorf("--redirect-uri must be specified")
	}

	if cfg.Scopes == "" {
		return fmt.Errorf("--scopes must be specified")
	}

	return nil
}

func executeLogin(cfg *LoginConfig) error {
	if err := checkLoginConfig(cfg); err != nil {
		return err
	}

	serialisedConfig, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		log.Errorln("Failed to serialise configuration as JSON:", err)
	} else {
		log.Debugf("Loaded config:\n%s", string(serialisedConfig))
	}

	client := &http.Client{Timeout: time.Second * 10}
	context := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(context, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("Failed to get OIDC provider: %s", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       append(strings.Split(cfg.Scopes, ","), oidc.ScopeOpenID),
	}

	// Generate a random UUID to use as the OAuth2 state
	newUUID, err := uuid.NewUUID()
	if err != nil {
		return fmt.Errorf("Failed to get UUID: %s", err)
	}

	state := newUUID.String()
	response, err := client.Get(oauth2Config.AuthCodeURL(state))
	if err != nil {
		return fmt.Errorf("Failed to get login URI: %s", err)
	}

	loginURI := response.Request.URL
	log.Debugln("Received login URI", loginURI)

	// TODO: Temporarily using environment variables
	ldapUsername := os.Getenv("LDAP_USERNAME")
	ldapPassword := os.Getenv("LDAP_PASSWORD")
	callbackURI, err := connector.Dex(loginURI, ldapUsername, ldapPassword)
	if err != nil {
		return fmt.Errorf("Failed to log in: %s", err)
	}

	code := callbackURI.Query().Get("code")
	if code == "" {
		return fmt.Errorf("Failed to extract code from %s", callbackURI)
	}

	returnedState := callbackURI.Query().Get("state")
	if code == "" {
		return fmt.Errorf("Failed to extract state from %s", callbackURI)
	}

	if returnedState != state {
		return fmt.Errorf("Returned state '%s' did not match '%s'", returnedState, state)
	}

	token, err := oauth2Config.Exchange(context, code)
	if err != nil {
		return fmt.Errorf("Failed to fetch token: %s", err)
	}

	serialisedToken, err := json.MarshalIndent(token, "", "    ")
	if err != nil {
		log.Errorln("Failed to serialise token as JSON:", err)
	} else {
		log.Debugf("Token contents (note: ID token is not included):\n%+v", string(serialisedToken))
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("Token extra was missing 'id_token' field or it did not contain a string")
	}
	log.Debugln("Fetched ID token:", rawIDToken)

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(context, rawIDToken)
	if err != nil {
		return fmt.Errorf("Failed verify ID token: %s", err)
	}

	claims := new(interface{})
	if err = idToken.Claims(&claims); err != nil {
		return fmt.Errorf("Failed to extract claims from ID token: %s", err)
	}

	serialisedClaims, err := json.MarshalIndent(claims, "", "    ")
	if err != nil {
		log.Errorln("Failed to serialise claims as JSON:", err)
	} else {
		log.Debugf("Token contents:\n%s", string(serialisedClaims))
	}

	kubectlCmd := exec.Command(
		"kubectl",
		"config",
		"set-credentials",
		cfg.User,
		"--auth-provider=oidc",
		"--auth-provider-arg=idp-issuer-url="+cfg.Issuer,
		"--auth-provider-arg=client-id="+cfg.ClientID,
		"--auth-provider-arg=client-secret="+cfg.ClientSecret,
		"--auth-provider-arg=id-token="+rawIDToken,
		"--auth-provider-arg=refresh-token="+token.RefreshToken,
	)

	out, err := kubectlCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to update kubeconfig file: %s", string(out))
	}
	fmt.Printf("Set user '%s' with OIDC token\n", cfg.User)

	for _, cluster := range clusters {
		if err := setContext(cfg.User, cluster.Name); err != nil {
			return err
		}
	}

	fmt.Println("Updated kubeconfig file")
	return nil
}

func setContext(user string, clusterName string) error {
	context := user + "@" + clusterName

	kubectlCmd := exec.Command(
		"kubectl",
		"config",
		"set-context",
		context,
		"--user="+user,
		"--cluster="+clusterName,
	)

	log.Debugf("Running command: %v", kubectlCmd.Args)
	out, err := kubectlCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to update kubeconfig file: %s", string(out))
	}

	fmt.Printf("Set context '%s'\n", context)
	return nil
}
