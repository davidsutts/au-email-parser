package main

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
	"google.golang.org/api/sheets/v4"
)

const (
	hostAndPort     = "localhost:8080"
	basketballEmail = "basketball@adelaideunisport.com.au"
	sheetID         = "12KmIFrkqd2G9Mavxcez8VA6kcZ9O-oKGJzcewQRgLrU"
	productFilter   = "Fitness Hub"
	defaultPort     = 8080
)

var (
	sessionKey   = []byte("ewtRjTxgXjYiRU/AzZOwWAfmkhZ42FDb/qlav2lg5GM=")
	config       *oauth2.Config
	projBucket   *storage.BucketHandle
	sessionStore *sessions.CookieStore
	service      *gmail.Service
	client       *http.Client
	port         int
	tok          *oauth2.Token
)

func main() {

	host := "" // determined by GAE
	v := os.Getenv("PORT")
	if v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			port = i
		}
	} else {
		port = defaultPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login/", loginHandler)
	mux.HandleFunc("/oauth2redirect/", oauthHandler)
	mux.HandleFunc("/", indexHandler)

	initialise()

	log.Printf("✅ Server started on %s:%d", host, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", host, port), mux))
}

func initialise() {

	gob.Register(&oauth2.Token{})

	var secrets struct {
		Project struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"web"`
	}

	sessionStore = sessions.NewCookieStore(sessionKey)

	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, storage.WithJSONReads())
	if err != nil {
		log.Panic("failed to get new storage client:", err)
	}

	projBucket = storageClient.Bucket("au-email-parser-tokens")

	// Read secrets
	reader, err := projBucket.Object("oauth2_secrets.json").NewReader(ctx)
	if err != nil {
		log.Fatal("could not get secrets reader:", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal("unable to read secrets from bucket")
	}

	err = json.Unmarshal(data, &secrets)
	if err != nil {
		log.Fatal("unable to unmarshal secrets:", err)
	}

	config = &oauth2.Config{
		RedirectURL:  "http://" + hostAndPort + "/oauth2redirect",
		ClientID:     secrets.Project.ClientID,
		ClientSecret: secrets.Project.ClientSecret,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	config.Scopes = append(config.Scopes, gmail.GmailReadonlyScope)

	// Get token from bucket.
	tokReader, err := projBucket.Object(basketballEmail + "-token.json").NewReader(ctx)
	if err != nil {
		log.Panic("unable to get reader for auth token")
	}

	tokData, err := io.ReadAll(tokReader)
	err = tokReader.Close()
	if err != nil {
		log.Panic("unable to read token from bucket:", err)
	}

	tok := &oauth2.Token{}
	json.Unmarshal(tokData, tok)

	client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	service, err = gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Println("unable to create new service:", err)
		return
	}

	log.Println("✅ Oauth2 Configured")
	log.Println("✅ Process Initialised")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK :)"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()

	sess, err := sessionStore.New(r, state)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create new session: %v", err)
		return
	}

	err = sess.Save(r, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save session: %v", err)
		return
	}

	url := config.AuthCodeURL(state, oauth2.ApprovalForce, oauth2.AccessTypeOffline)
	log.Println("redirecting to google oauth2 flow")
	http.Redirect(w, r, url, http.StatusFound)
}

func oauthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	_, err := sessionStore.Get(r, r.FormValue("state"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to get session with state: %v", err)
		return
	}

	tok, err := config.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		log.Println("failed to login:", err)
		return
	}

	// Create a new session with the received token.
	sess, err := sessionStore.New(r, "au-parser-auth")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session: %v", err)
		return
	}
	sess.Values["token"] = tok

	client := oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	peopleService, err := people.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get peopleService:", err)
		return
	}

	person, err := peopleService.People.Get("people/me").PersonFields("emailAddresses").Do()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get profile info:", err)
		return
	}

	email := person.EmailAddresses[0].Value

	// write  secrets
	writer := projBucket.Object(basketballEmail + "-token.json").NewWriter(ctx)
	if err != nil {
		log.Fatal("could not get secrets writer:", err)
	}

	binTok, err := json.Marshal(tok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to marshal token: %v", err)
		return
	}

	_, err = writer.Write(binTok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to write token to bucket: %v", err)
		return
	}
	err = writer.Close()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to write token to bucket: %v", err)
		return
	}

	log.Printf("wrote new token to bucket with email: %s", email)

	sess.Values["email"] = email
	client = oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	service, err = gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to override gmail service: %v", err)
		return
	}

	err = sess.Save(r, w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save session: %v", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func verifyProfile(w http.ResponseWriter, r *http.Request) (string, *oauth2.Token) {
	sess, err := sessionStore.Get(r, "au-parser-auth")
	if err != nil {
		log.Printf("user not signed in, redirecting (err fetching session: %v)", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", nil
	}
	tok, ok := sess.Values["token"].(*oauth2.Token)
	if !ok {
		log.Println("user not signed in, redirecting (bad token)")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", nil
	}

	if !tok.Valid() {
		log.Println("invalid token, redirecting")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", nil
	}

	return sess.Values["email"].(string), tok
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		// Redirect all invalid URLs to the root homepage.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	list, err := service.Users.Messages.List(basketballEmail).Q(productFilter).LabelIds("Label_7006746477333341141").Do()
	if err != nil {
		log.Printf("unable to get emails with given label: %v", err)
		redirectToSheet(w, r)
		return
	}

	if len(list.Messages) == 0 {
		log.Printf("unable to find any matching emails")
		redirectToSheet(w, r)
		return
	}
	length := len(list.Messages)

	ctx := context.Background()
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/spreadsheets,https://www.googleapis.com/auth/drive.file")
	if err != nil {
		log.Println("could not find default credentials:", err)
		redirectToSheet(w, r)
		return
	}

	sheetsService, err := sheets.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		log.Println("failed to get sheets service:", err)
		redirectToSheet(w, r)
		return
	}

	values, err := sheetsService.Spreadsheets.Values.Get("12KmIFrkqd2G9Mavxcez8VA6kcZ9O-oKGJzcewQRgLrU", "ID!A:A").Do()
	if err != nil {
		log.Println("failed to get spreadsheet values:", err)
		redirectToSheet(w, r)
		return
	}
	readIDs := make(map[string]bool)
	if len(values.Values) >= 0 {
		for _, v := range values.Values {
			readIDs[v[0].(string)] = true
		}
	}

	newEmailsLen := length - len(values.Values)
	log.Printf("got %d emails, parsing %d new emails", length, newEmailsLen)

	if newEmailsLen == 0 {
		redirectToSheet(w, r)
		return
	}

	var wg sync.WaitGroup
	ch := make(chan Order, length)
	ids := &sheets.ValueRange{
		Values: [][]interface{}{},
	}
	for _, message := range list.Messages {
		time.Sleep(10 * time.Millisecond)

		if readIDs[message.Id] {
			continue
		} else {
			ids.Values = append(ids.Values, []interface{}{message.Id})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Retrieve the full message to access its payload and headers
			fullMessage, err := service.Users.Messages.Get(basketballEmail, message.Id).Do()
			if err != nil {
				log.Println("unable to retrieve full message:", err)
				return
			}

			if fullMessage.Payload == nil || len(fullMessage.Payload.Headers) == 0 {
				log.Println("message has no payload or headers")
				return
			}

			// Extract the body from the email
			orders := getBodyFromPayload(fullMessage.Payload)

			if orders == nil {
				return
			}

			// Add the body to the output
			for _, order := range *orders {
				ch <- order
			}
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

	_, err = sheetsService.Spreadsheets.Values.Append(sheetID, "ID!A:A", ids).ValueInputOption("RAW").Do()
	if err != nil {
		log.Println("failed to append spreadsheet values:", err)
		redirectToSheet(w, r)
		return
	}

	sort.Slice(orders, func(i, j int) bool {
		return orders[i].Time < orders[j].Time
	})

	ordersToWrite := &sheets.ValueRange{
		Values: [][]interface{}{},
	}
	for _, order := range orders {
		ordersToWrite.Values = append(ordersToWrite.Values, []interface{}{order.Time, order.Name})
	}

	_, err = sheetsService.Spreadsheets.Values.Append(sheetID, "Sessions!A:B", ordersToWrite).
		ValueInputOption("RAW").
		Do()
	if err != nil {
		log.Println("failed to append spreadsheet values:", err)
		redirectToSheet(w, r)
		return
	}

	redirectToSheet(w, r)

}

func redirectToSheet(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://docs.google.com/spreadsheets/d/"+sheetID, http.StatusFound)
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
		if !strings.Contains(product, "Fitness Hub Training Session") {
			continue
		}
		// Define the regular expression pattern to match content inside brackets
		re := regexp.MustCompile(`\((.*)\)`)

		// Find all matches
		option := re.FindString(product)

		// Trim Brackets.
		option = strings.Trim(option, "()")

		*orders = append(*orders, Order{Name: name, Time: option})
	}

	if len(*orders) == 0 {
		return nil
	}

	log.Println(orders)

	return orders

}
