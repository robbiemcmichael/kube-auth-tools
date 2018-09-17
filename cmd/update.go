package cmd

import (
	"fmt"
	"os/exec"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update kubeconfig file",
	RunE: func(cmd *cobra.Command, args []string) error {
		return executeUpdate(clusters)
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func executeUpdate(clusters []Cluster) error {
	for _, cluster := range clusters {
		if err := setCluster(cluster); err != nil {
			return err
		}
	}

	fmt.Println("Updated kubeconfig file")
	return nil
}

func setCluster(cluster Cluster) error {
	args := []string{
		"config",
		"set-cluster",
		cluster.Name,
		"--server=" + cluster.Cluster.Server,
		"--insecure-skip-tls-verify=" + strconv.FormatBool(cluster.Cluster.InsecureSkipTLSVerify),
	}

	if !cluster.Cluster.InsecureSkipTLSVerify {
		args = append(args, "--embed-certs=true")
		args = append(args, "--certificate-authority="+rootConfig.ConfigDir+"/"+cluster.Cluster.CertificateAuthority)
	}

	kubectlCmd := exec.Command("kubectl", args...)

	log.Debugf("Running command: %v", kubectlCmd.Args)
	out, err := kubectlCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to update kubeconfig file: %s", string(out))
	}

	fmt.Printf("Set cluster '%s'\n", cluster.Name)
	return nil
}
