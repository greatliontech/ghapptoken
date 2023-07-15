package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ghapptoken",
	Short: "A CLI tool to generate a GitHub access token from a GitHub App istallation",
	RunE:  rootCmdRunE,
}

var rootCmdFlags = struct {
	AppID             string
	PrivateKeyPath    string
	Repository        string
	AppInstallationID int64
}{}

func main() {
	rootCmd.Flags().StringVarP(&rootCmdFlags.AppID, "app-id", "a", "", "GitHub App ID")
	rootCmd.Flags().StringVarP(&rootCmdFlags.PrivateKeyPath, "private-key-path", "p", "", "Path to the private key file")
	rootCmd.Flags().Int64VarP(&rootCmdFlags.AppInstallationID, "app-installation-id", "i", 0, "GitHub App installation ID")

	if err := rootCmd.MarkFlagRequired("app-id"); err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.MarkFlagRequired("private-key-path"); err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.MarkFlagRequired("app-installation-id"); err != nil {
		log.Fatal(err)
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func rootCmdRunE(cmd *cobra.Command, args []string) error {

	data, err := ioutil.ReadFile(rootCmdFlags.PrivateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	token, err := credentialsToJWT(rootCmdFlags.AppID, data)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	client := github.NewTokenClient(ctx, token)

	it, _, err := client.Apps.CreateInstallationToken(ctx, rootCmdFlags.AppInstallationID, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(*it.Token)

	return nil
}

func credentialsToJWT(appId string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 10).Unix(),
		"iss": appId,
	})
	return token.SignedString(privKey)
}
