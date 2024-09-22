package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	hostAndPort     = "localhost:8080"
	basketballEmail = "basketball@adelaideunisport.com.au"
)

var (
	sessionKey   = []byte("ewtRjTxgXjYiRU/AzZOwWAfmkhZ42FDb/qlav2lg5GM=")
	config       *oauth2.Config
	projBucket   *storage.BucketHandle
	sessionStore *sessions.CookieStore
	service      *gmail.Service
)

func main() {

	mux := http.NewServeMux()

	// mux.HandleFunc("/check/emails/", checkHandler)
	// mux.HandleFunc("/login/", loginHandler)
	// mux.HandleFunc("/oauth2redirect/", oauthHandler)
	mux.HandleFunc("/", indexHandler)

	initialise()

	log.Println("✅ Server started on ", hostAndPort)
	http.ListenAndServe(hostAndPort, mux)
}

func initialise() {

	ctx := context.Background()

	var err error
	storageClient, err := storage.NewClient(ctx, storage.WithJSONReads())
	if err != nil {
		log.Panic("failed to get new storage client:", err)
	}

	projBucket = storageClient.Bucket("au-email-parser-tokens")

	// Get token from bucket.
	tokReader, err := projBucket.Object(basketballEmail + "-token.json").NewReader(ctx)
	if err != nil {
		log.Panic("unable to get reader for auth token")
	}

	data, err := io.ReadAll(tokReader)
	err = tokReader.Close()
	if err != nil {
		log.Panic("unable to read token from bucket:", err)
	}

	tok := &oauth2.Token{}
	json.Unmarshal(data, tok)

	client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	service, err = gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Println("unable to create new service:", err)
		return
	}

	log.Println("✅ Process Initialised")
}

// func authConfig() {
// 	gob.Register(&oauth2.Token{})

// 	ctx := context.Background()

// 	if config != nil {
// 		log.Println("already configured")
// 		return
// 	}

// 	if projBucket == nil {
// 		log.Fatal("bucket is nil")
// 	}

// 	// Read secrets
// 	reader, err := projBucket.Object("oauth2_secrets.json").NewReader(ctx)
// 	if err != nil {
// 		log.Fatal("could not get secrets reader:", err)
// 	}

// 	data, err := io.ReadAll(reader)
// 	if err != nil {
// 		log.Fatal("unable to read secrets from bucket")
// 	}

// 	var secrets struct {
// 		Project struct {
// 			ClientID     string `json:"client_id"`
// 			ClientSecret string `json:"client_secret"`
// 		} `json:"web"`
// 	}

// 	err = json.Unmarshal(data, &secrets)
// 	if err != nil {
// 		log.Fatal("unable to unmarshal secrets:", err)
// 	}

// 	config = &oauth2.Config{
// 		RedirectURL:  "http://" + hostAndPort + "/oauth2redirect",
// 		ClientID:     secrets.Project.ClientID,
// 		ClientSecret: secrets.Project.ClientSecret,
// 		Scopes:       []string{"email", "profile"},
// 		Endpoint:     google.Endpoint,
// 	}

// 	config.Scopes = append(config.Scopes, gmail.GmailReadonlyScope)

// 	sessionStore = sessions.NewCookieStore(sessionKey)

// 	log.Println("✅ Oauth2 Configured")
// }

// func checkHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("OK :)"))
// }

// func loginHandler(w http.ResponseWriter, r *http.Request) {
// 	state := uuid.New().String()

// 	sess, err := sessionStore.New(r, state)
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "unable to create new session: %v", err)
// 		return
// 	}

// 	err = sess.Save(r, w)
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "unable to save session: %v", err)
// 		return
// 	}

// 	url := config.AuthCodeURL(state, oauth2.ApprovalForce, oauth2.AccessTypeOffline)
// 	log.Println("redirecting to google oauth2 flow")
// 	http.Redirect(w, r, url, http.StatusFound)
// }

// func oauthHandler(w http.ResponseWriter, r *http.Request) {
// 	ctx := context.Background()

// 	_, err := sessionStore.Get(r, r.FormValue("state"))
// 	if err != nil {
// 		writeError(w, http.StatusBadRequest, "unable to get session with state: %v", err)
// 		return
// 	}

// 	tok, err := config.Exchange(ctx, r.FormValue("code"))
// 	if err != nil {
// 		log.Println("failed to login:", err)
// 		return
// 	}

// 	// Create a new session with the received token.
// 	sess, err := sessionStore.New(r, "au-parser-auth")
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "could not create session: %v", err)
// 		return
// 	}
// 	sess.Values["token"] = tok

// 	client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
// 	peopleService, err := people.NewService(ctx, option.WithHTTPClient(client))
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "failed to get peopleService:", err)
// 		return
// 	}

// 	person, err := peopleService.People.Get("people/me").PersonFields("emailAddresses").Do()
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "failed to get profile info:", err)
// 		return
// 	}

// 	email := person.EmailAddresses[0].Value

// 	sess.Values["email"] = email
// 	err = sess.Save(r, w)
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, "unable to save session: %v", err)
// 		return
// 	}
// 	http.Redirect(w, r, "/", http.StatusFound)
// }

// func verifyProfile(w http.ResponseWriter, r *http.Request) (string, *oauth2.Token) {
// 	sess, err := sessionStore.Get(r, "au-parser-auth")
// 	if err != nil {
// 		log.Printf("user not signed in, redirecting (err fetching session: %v)", err)
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return "", nil
// 	}
// 	tok, ok := sess.Values["token"].(*oauth2.Token)
// 	if !ok {
// 		log.Println("user not signed in, redirecting (bad token)")
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return "", nil
// 	}

// 	if !tok.Valid() {
// 		log.Println("invalid token, redirecting")
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return "", nil
// 	}

// 	return sess.Values["email"].(string), tok
// }

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// ctx := context.Background()s

	if r.URL.Path != "/" {
		// Redirect all invalid URLs to the root homepage.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// email, tok := verifyProfile(w, r)
	// if email != basketballEmail && email != "dsutton1202@gmail.com" {
	// 	fmt.Fprint(w, "This service is only designed for 'basketball@adelaideunisport.com.au'")
	// 	return
	// }

	// tokenWriter := projBucket.Object(basketballEmail + "-token.json").NewWriter(ctx)
	// jsonTok, err := json.Marshal(tok)
	// if err != nil {
	// 	writeError(w, http.StatusInternalServerError, "could not marshal token: %v", err)
	// 	return
	// }
	// n, err := tokenWriter.Write(jsonTok)
	// err = tokenWriter.Close()
	// if err != nil {
	// 	writeError(w, http.StatusInternalServerError, "unable to write token to bucket: %v", err)
	// 	return
	// }
	// log.Printf("wrote %d bytes", n)

	// client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	// service, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	// if err != nil {
	// 	log.Println("unable to create new service:", err)
	// 	return
	// }

	list, err := service.Users.Messages.List(basketballEmail).LabelIds("Label_7006746477333341141").Do()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to get emails with given label:", err)
		return
	}

	if len(list.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "unable to find any matching emails")
		return
	}
	length := len(list.Messages)
	log.Printf("got %d emails", length)

	var wg sync.WaitGroup
	ch := make(chan Order, length)
	wg.Add(length)
	for _, message := range list.Messages {
		time.Sleep(10 * time.Millisecond)
		go func() {
			// Retrieve the full message to access its payload and headers
			fullMessage, err := service.Users.Messages.Get(basketballEmail, message.Id).Do()
			if err != nil {
				log.Println("unable to retrieve full message:", err)
				wg.Done()
				return
			}

			if fullMessage.Payload == nil || len(fullMessage.Payload.Headers) == 0 {
				log.Println("message has no payload or headers")
				wg.Done()
				return
			}

			// Extract the body from the email
			orders := getBodyFromPayload(fullMessage.Payload)

			if orders == nil {
				wg.Done()
				return
			}

			// Add the body to the output
			for _, order := range *orders {
				ch <- order
			}
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	orders := []Order{}
	for order := range ch {
		orders = append(orders, order)
	}
	wg.Wait()

	sort.Slice(orders, func(i, j int) bool {
		return orders[i].Time < orders[j].Time
	})

	var heading string
	for _, order := range orders {
		if order.Time != heading {
			heading = order.Time
			fmt.Fprintln(w, heading)
		}
		fmt.Fprintf(w, "\t%s\n", order.Name)
	}
	log.Println("Parsed all messages")

}

func writeError(w http.ResponseWriter, statusCode int, msg string, args ...any) {
	log.Printf(msg, args...)
	w.WriteHeader(statusCode)
	w.Write([]byte(fmt.Sprintf(msg, args...)))
}

type Order struct {
	Name string
	Time string
}

// Helper function to get the body of the email
func getBodyFromPayload(payload *gmail.MessagePart) *[]Order {
	if payload == nil {
		return nil
	}

	// If there is no multipart, the body is directly in the payload
	if len(payload.Parts) == 0 {
		if payload.Body.Data != "" {
			return decodeMessage(payload.Body.Data)
		}
		return nil
	}

	// Loop through parts to find the plain text part (or HTML part if needed)
	for _, part := range payload.Parts {
		if part.MimeType == "text/plain" {
			return decodeMessage(part.Body.Data)
		}
	}

	return nil
}

// Helper function to decode base64url-encoded email body
func decodeMessage(data string) *[]Order {
	decodedData, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		log.Println("Error decoding message:", err)
		return nil
	}

	bodyStr := string(decodedData)

	// Define the start and end markers for the section you want to extract
	startMarker := "Name:"
	endMarker := "Total"

	// Find the position of the start and end markers
	startIndex := strings.Index(bodyStr, startMarker)
	endIndex := strings.Index(bodyStr, endMarker)

	// Check if both markers were found
	if startIndex == -1 || endIndex == -1 || startIndex > endIndex {
		log.Println("couldn't find relevant portion of email")
		// log.Println(bodyStr)
		// Extract the relevant portion of the email body
		return nil
	}
	bodyStr = bodyStr[startIndex : endIndex+len(endMarker)]

	lines := strings.Split(bodyStr, "\n")
	if len(lines) < 23 {
		log.Println("email body doesn't match pattern")
		return nil
	}

	orders := &[]Order{}

	// Get the name of the person.
	nameLine := strings.Split(lines[0], ":")
	if len(nameLine) < 2 {
		log.Println("email body doesn't match pattern")
		return nil
	}
	name := strings.TrimSpace(nameLine[1])

	// For each product:
	for i := 14; i < len(lines)-1; i += 7 {
		product := strings.TrimSpace(lines[i])
		if !strings.Contains(product, "Winter Dinner") {
			continue
		}
		// Define the regular expression pattern to match content inside brackets
		re := regexp.MustCompile(`\((.*)\)`)

		// Find all matches
		option := re.FindString(product)
		*orders = append(*orders, Order{Name: name, Time: option})
	}

	if len(*orders) == 0 {
		return nil
	}

	return orders

}
