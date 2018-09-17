package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type RootConfig struct {
	ConfigDir string
	Debug     bool
}

type Cluster struct {
	Name    string
	Cluster ClusterSpec
}

type ClusterSpec struct {
	Server                string
	CertificateAuthority  string
	InsecureSkipTLSVerify bool
}

var rootConfig RootConfig
var clusters []Cluster

var rootCmd = &cobra.Command{
	Use:   "kube-auth-tools",
	Short: "Command line tools to help with Kubernetes OIDC authentication",
}

func init() {
	cobra.OnInitialize(initRoot)

	home, err := homedir.Dir()
	if err != nil {
		fmt.Println("Failed to get home directory:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().StringVar(&rootConfig.ConfigDir, "config-dir", home+"/.kube/plugins/kube-auth-tools", "config directory")
	rootCmd.PersistentFlags().BoolVar(&rootConfig.Debug, "debug", false, "debug mode")
}

func initRoot() {
	if rootConfig.Debug {
		log.SetLevel(log.DebugLevel)
	}

	viper.AddConfigPath(rootConfig.ConfigDir)
	viper.SetConfigName("config")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Failed to read config file:", err)
		os.Exit(1)
	}

	if err := viper.UnmarshalKey("clusters", &clusters); err != nil {
		fmt.Println("Failed to unmarshal clusters:", err)
		os.Exit(1)
	}

	if clusters == nil {
		fmt.Println("No clusters in config file")
		os.Exit(1)
	}
	log.Debugf("Clusters: %+v\n", clusters)

	initLogin()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
