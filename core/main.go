package main

import (
	"fmt"
	"os"
	"rrcore/cmd/colors"
	"rrcore/cmd/deploy"
	"rrcore/cmd/destroy"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   colors.Cyan("rapidradar"),
	Short: colors.Cyan("CLI tool for rapidradar deployment"),
	Long:  colors.Cyan(`RapidRadar CLI tool for managing deployment actions like deploy and destroy.`),
}

func init() {
	rootCmd.AddCommand(deploy.Cmd)
	rootCmd.AddCommand(destroy.Cmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
