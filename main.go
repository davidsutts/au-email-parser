package main

import (
	"context"
	"encoding/base64"
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
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
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
	client     *http.Client
	config     *oauth2.Config
	projBucket *storage.BucketHandle
	service    *gmail.Service
	port       int
	tok        *oauth2.Token
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

	mux.HandleFunc("/", indexHandler)

	initialise()

	log.Printf("✅ Server started on %s:%d", host, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", host, port), mux))
}

func initialise() {

	ctx := context.Background()

	var err error
	storageClient, err := storage.NewClient(ctx, storage.WithJSONReads())
	if err != nil {
		log.Fatal("failed to get new storage client:", err)
	}

	projBucket = storageClient.Bucket("au-email-parser-tokens")

	// Get token from bucket.
	tokReader, err := projBucket.Object(basketballEmail + "-token.json").NewReader(ctx)
	if err != nil {
		log.Fatal("unable to get reader for auth token")
	}

	data, err := io.ReadAll(tokReader)
	if err != nil {
		log.Println("readall returned error:", err)
	}
	err = tokReader.Close()
	if err != nil {
		log.Fatal("unable to read token from bucket:", err)
	}

	tok = &oauth2.Token{}
	err = json.Unmarshal(data, tok)
	if err != nil {
		log.Fatal("unable to unmarshal token data:", err)
	}

	// Read secrets
	reader, err := projBucket.Object("oauth2_secrets.json").NewReader(ctx)
	if err != nil {
		log.Fatal("could not get secrets reader:", err)
	}

	data, err = io.ReadAll(reader)
	if err != nil {
		log.Fatal("unable to read secrets from bucket")
	}

	var secrets struct {
		Project struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"web"`
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

	client = oauth2.NewClient(ctx, config.TokenSource(ctx, tok))
	if client == nil {
		log.Fatal("got nil client")
	}
	service, err = gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Println("unable to create new service:", err)
		return
	}

	log.Println("✅ Process Initialised")
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		// Redirect all invalid URLs to the root homepage.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	list, err := service.Users.Messages.List(basketballEmail).LabelIds("Label_7006746477333341141").Q(productFilter).Do()
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
		// log.Println("couldn't find relevant portion of email")
		// log.Println(bodyStr)
		// Extract the relevant portion of the email body
		return nil
	}
	bodyStr = bodyStr[startIndex : endIndex+len(endMarker)]

	lines := strings.Split(bodyStr, "\n")
	if len(lines) < 23 {
		// log.Println("email body doesn't match pattern")
		return nil
	}

	orders := &[]Order{}

	// Get the name of the person.
	nameLine := strings.Split(lines[0], ":")
	if len(nameLine) < 2 {
		// log.Println("email body doesn't match pattern")
		return nil
	}
	name := strings.TrimSpace(nameLine[1])

	// For each product:
	for i := 14; i < len(lines)-2; i += 7 {
		product := strings.TrimSpace(lines[i])
		if !strings.Contains(product, productFilter) {
			continue
		}
		// Define the regular expression pattern to match content inside brackets
		re := regexp.MustCompile(`\((.*)\)`)

		// Find all matches
		option := re.FindString(product)
		if option == "" {
			continue
		}
		*orders = append(*orders, Order{Name: name, Time: option})
	}

	if len(*orders) == 0 {
		return nil
	}

	return orders

}
