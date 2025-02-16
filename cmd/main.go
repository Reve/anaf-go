package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Reve/anaf-go/anaf"
)

func main() {
	// Example credentials (replace with real data)
	clientID := "YOUR_CLIENT_ID"
	clientSecret := "YOUR_CLIENT_SECRET"
	redirectURI := "https://example.com/oauth/callback"
	accessToken := "YOUR_INITIAL_ACCESS_TOKEN"
	refreshToken := "YOUR_REFRESH_TOKEN"

	anafClient := anaf.NewEinvoiceApi(accessToken, refreshToken, clientID, clientSecret, redirectURI, false)

	result, err := anafClient.Hello(context.Background())

	if err != nil {
		log.Fatalf("Hello() failed: %v", err)
	}

	fmt.Println("Hello result:", result)
}
