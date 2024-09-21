package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	hostAndPort = "localhost:8080"
)

var (
	config *oauth2.Config
	bucket *storage.BucketHandle
)

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("/check/emails/", checkHandler)
	mux.HandleFunc("/login/", loginHandler)
	mux.HandleFunc("/oauth2redirect/", oauthHandler)

	authConfig()
	storeConfig()

	log.Println("listening on", hostAndPort)
	http.ListenAndServe(hostAndPort, mux)
}

func authConfig() {
	if config != nil {
		log.Println("already configured")
		return
	}
	config = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/oauth2redirect",
		ClientID:     "XXX",
		ClientSecret: "XXX",
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	config.Scopes = append(config.Scopes, gmail.GmailReadonlyScope)
}

func storeConfig() {
	log.Println("configuring storage")

	ctx := context.Background()

	var err error
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Panic("failed to get new storage client:", err)
	}

	bucket = storageClient.Bucket("au-email-parser-tokens")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK :)"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := config.AuthCodeURL("", oauth2.ApprovalForce, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
	log.Println("redirecting to google oauth2 flow")
}

func oauthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	tok, err := config.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		log.Println("failed to login:", err)
		return
	}

	bucket.Object(google.)

	client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	service, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Println("unable to create new service:", err)
		return
	}

	resp, err := service.Users.Messages.
		List("dsutton1202@gmail.com").
		MaxResults(10).
		Q("New shop purchase").
		Do()

	if err != nil {
		log.Println("failed to make call:", err)
		return
	}

	log.Printf("Response:\n\t%+v", resp)

	w.Write([]byte(fmt.Sprintf("%v", resp.Messages)))

}
