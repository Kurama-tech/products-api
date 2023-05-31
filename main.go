package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	//"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/minio/minio-go"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ItemGet struct {
	ID            primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Images        []string           `bson:"images" json:"images"`
	Type 		  string   			 `json:"type"`
	Parent		  string   			 `json:"parent"`
	Status        string             `json:"status"`
	TableAttached []TableAttachType  `bson:"tables" json:"tables"`
}
type Item struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Images        []string `bson:"images" json:"images"`
	Type 		  string   `json:"type"`
	Parent		  string   `json:"parent"`
	Status        string   `json:"status"`
	TableAttached []TableAttachType `bson:"tables" json:"tables"`
}

type NavbarType struct {
	Name string `json:"name"`
	Href string `json:"href"`
}


type TableAttachType struct {
	ID   primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name string `json:"name"`
}

type Tables struct {
	Name string            `json:"name"`
	Data []json.RawMessage `json:"data"`
}

type HomeCarousel struct {
	Name string            `json:"name"`
	URL string `json:"url"`
}
type HomeCarouselGet struct {
	ID   primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name string            `json:"name"`
	URL string `json:"url"`
}

type TablesGet struct {
	ID   primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name string             `json:"name"`
	Data []json.RawMessage  `json:"data"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type TableData struct {
	Name string `json:"name"`
}

type Table struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	TableHeadings []TableData `json:"tableheading"`
	TableData     []TableData `json:"tabledata"`
}

const Database = "jwc"
const minioURL = "167.71.233.124:9000"

func getEnv(Environment string) (string, error) {
	variable := os.Getenv(Environment)
	if variable == "" {
		fmt.Println(Environment + ` Environment variable is not set`)
		return "", errors.New("env Not Set Properly")
	} else {
		fmt.Printf(Environment+" variable value is: %s\n", variable)
		return variable, nil
	}
}
func main() {
	// MongoDB client options

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},        // All origins
		AllowedMethods:   []string{"POST", "GET", "PUT", "DELETE"}, // Allowing only get, just an example
		AllowedHeaders:   []string{"Set-Cookie", "Content-Type"},
		ExposedHeaders:   []string{"Set-Cookie"},
		AllowCredentials: true,
		Debug:            true,
	})

	// Get the value of the "ENV_VAR_NAME" environment variable
	mongoURL, err := getEnv("MONGO_URL")
	if err != nil {
		os.Exit(1)
	}

	username, err := getEnv("JWT_USER")
	if err != nil {
		os.Exit(1)
	}
	password, err := getEnv("JWT_PASSWORD")
	if err != nil {
		os.Exit(1)
	}

	jwtk, err := getEnv("JWT_KEY")
	if err != nil {
		os.Exit(1)
	}

	minioKey, err := getEnv("MINIO_KEY")
	if err != nil {
		os.Exit(1)
	}
	minioSecret, err := getEnv("MINIO_SECRET")
	if err != nil {
		os.Exit(1)
	}

	var jwtKey = []byte(jwtk)

	clientOptions := options.Client().ApplyURI(mongoURL)

	// Create a new MongoDB client
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	minioClient, err := minio.New(minioURL, minioKey, minioSecret, false)
	if err != nil {
		log.Fatalln(err)
	}

	// Create a new router using Gorilla Mux
	router := mux.NewRouter()

	// Define a POST route to add an item to a collection
	router.HandleFunc("/items", addItem(client)).Methods("POST")

	router.HandleFunc("/items", getItems(client)).Methods("GET")

	router.HandleFunc("/items/disabled", getDisabledItems(client)).Methods("GET")

	router.HandleFunc("/items/{id}", getItem(client)).Methods("GET")

	// Define a DELETE route to delete an item from a collection
	router.HandleFunc("/items/{id}", deleteItem(client)).Methods("DELETE")

	router.HandleFunc("/items/disabled/{id}", disableItem(client)).Methods("DELETE")

	router.HandleFunc("/items/enabled/{id}", enableItem(client)).Methods("GET")

	router.HandleFunc("/upload", Upload(minioClient)).Methods("POST")

	// Define a PUT route to edit an item in a collection
	router.HandleFunc("/items/{id}", editItem(client)).Methods("PUT")

	router.HandleFunc("/home", addHomeItem(client)).Methods("POST")
	router.HandleFunc("/home", getHomeItems(client)).Methods("GET")
	router.HandleFunc("/home/{id}", deleteHomeItem(client)).Methods("DELETE")

	router.HandleFunc("/tables", addTable(client)).Methods("POST")
	router.HandleFunc("/tables/{id}", getTable(client)).Methods("GET")
	router.HandleFunc("/tables", getTables(client)).Methods("GET")
	router.HandleFunc("/tables/{id}", deleteTable(client)).Methods("DELETE")


	router.HandleFunc("/login", login(jwtKey, username, password)).Methods("POST")

	// Start the HTTP server
	log.Println("Starting HTTP server...")
	err = http.ListenAndServe(":8002", c.Handler(router))
	if err != nil {

		log.Fatal(err)
	}
}

func login(jwtKey []byte, username string, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var creds Credentials

		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Here, you should check the credentials against your database or other authentication system
		// For simplicity, we'll just hardcode a username and password
		if creds.Username != username || creds.Password != password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			Username: creds.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println(tokenString)

		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    tokenString,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			Expires:  expirationTime})

		fmt.Println(w)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Login Successful")
	}
}

func Upload(minioClient *minio.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the multipart form.
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the file headers from the form.
		files := r.MultipartForm.File["files"]


		var ImagePaths []string

		// Loop through the files and upload them to Minio.
		for _, fileHeader := range files {
			// Open the file.
			file, err := fileHeader.Open()
			if err != nil {
				fmt.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// Get the file name and extension.
			filename := fileHeader.Filename
			extension := filepath.Ext(filename)

			dotRemoved := extension[1:]

			// Generate a unique file name with the original extension.
			newFilename := fmt.Sprintf("%d%s", time.Now().UnixNano(), extension)
			newPath := "http://" + minioURL + "/jwc/" + newFilename
			ImagePaths = append(ImagePaths, newPath)

			log.Println(ImagePaths)

			// Upload the file to Minio.
			_, err = minioClient.PutObject("jwc", newFilename, file, fileHeader.Size, minio.PutObjectOptions{
				ContentType: "image/"+dotRemoved,
			})
			if err != nil {
				fmt.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		data, err := json.Marshal(ImagePaths)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the Content-Type header to application/json
		//w.Header().Set("Content-Type", "application/json")
		// Write the JSON data to the response

		// Send a success response.
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// addItem inserts a new item into the "items" collection in MongoDB
func addItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the request body into an Item struct
		var item Item
		err := json.NewDecoder(r.Body).Decode(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Println(item)

		// Insert the item into the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		_, err = collection.InsertOne(context.Background(), item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusCreated)
	}
}

// addItem inserts a new item into the "items" collection in MongoDB
func addHomeItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the request body into an Item struct
		var item HomeCarousel
		err := json.NewDecoder(r.Body).Decode(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Println(item)

		// Insert the item into the "items" collection in MongoDB
		collection := client.Database(Database).Collection("home")
		_, err = collection.InsertOne(context.Background(), item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusCreated)
	}
}

// deleteItem deletes an item from the "items" collection in MongoDB
func deleteItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the name parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		// Delete the item from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = collection.DeleteOne(context.Background(), bson.M{"_id": oid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusOK)
	}
}

// editItem updates an item in the "items" collection in MongoDB
func editItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the name parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		fmt.Println(id)

		// Parse the request body into an Item struct
		var item ItemGet
		err := json.NewDecoder(r.Body).Decode(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Println(item)

		// tables := item.TableAttached

		// Update the item in the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		filter := bson.M{"_id": item.ID}
		update := bson.M{"$set": bson.M{"name": item.Name, "description": item.Description, "tables": item.TableAttached, "status": item.Status, "images": item.Images}}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusOK)
	}
}

func disableItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the name parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		fmt.Println(id)

		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Update the item in the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		filter := bson.M{"_id": oid}
		update := bson.M{"$set": bson.M{"status": "disabled"}}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusOK)
	}
}

func enableItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the name parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		fmt.Println(id)

		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Update the item in the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		filter := bson.M{"_id": oid}
		update := bson.M{"$set": bson.M{"status": "active"}}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusOK)
	}
}

// getItems retrieves all items from the "items" collection in MongoDB
func getItems(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get all items from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		cursor, err := collection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []ItemGet
		for cursor.Next(context.Background()) {
			var item ItemGet
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}

		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// getItems retrieves all items from the "items" collection in MongoDB
func getDisabledItems(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get all items from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		cursor, err := collection.Find(context.Background(), bson.M{"status": "disabled"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []ItemGet
		for cursor.Next(context.Background()) {
			var item ItemGet
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}

		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// getNavBar retrieves all items from the "items" collection in MongoDB
func getNavBar(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get all items from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		cursor, err := collection.Find(context.Background(), bson.M{"type": "Parent"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []ItemGet
		for cursor.Next(context.Background()) {
			var item ItemGet
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}
		var Navitems []NavbarType
		for _, item := range items {
			var navi NavbarType
			navi.Name = item.Name
			navi.Href = item.Name
			Navitems = append(Navitems, navi)
		}


		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(Navitems)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// getItems retrieves all items from the "items" collection in MongoDB
func getItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		id := vars["id"]

		fmt.Println(id)
		// Get all items from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		oid, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cursor, err := collection.Find(context.Background(), bson.M{"_id": oid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []ItemGet
		for cursor.Next(context.Background()) {
			var item ItemGet
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}

		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// addTable
func addTable(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tables Tables

		/* body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Print the request body as a string
		fmt.Println(string(body)) */

		err := json.NewDecoder(r.Body).Decode(&tables)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Get the "tables" collection from the database
		collection := client.Database(Database).Collection("tables")

		// Insert the tables data into the collection
		_, err = collection.InsertOne(context.TODO(), tables)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Write a success response
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Data inserted successfully"))
	}
}

// getHome
func getHomeItems(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the id parameter from the request URL
		// Get all items from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("home")
		cursor, err := collection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []HomeCarouselGet
		for cursor.Next(context.Background()) {
			var item HomeCarouselGet
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}

		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
// getTable
func getTable(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the id parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		// Get the "tables" collection from the database
		collection := client.Database(Database).Collection("tables")

		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Define a filter to find the tables with the given id
		filter := bson.M{"_id": objID}

		// Execute the find operation and get the result as a single document
		var tables TablesGet
		err = collection.FindOne(context.TODO(), filter).Decode(&tables)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Encode the result as JSON and write it to the response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tables)
	}
}

func deleteHomeItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the id parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		// Get the "tables" collection from the database
		collection := client.Database(Database).Collection("home")

		// Convert the ID string to an ObjectId
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Define a filter to find the table with the given ID
		filter := bson.M{"_id": objID}

		// Delete the table matching the filter
		result, err := collection.DeleteOne(context.TODO(), filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if any document was deleted
		if result.DeletedCount == 0 {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}

		// Write a success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Item deleted successfully"))
	}
}

func deleteTable(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the id parameter from the request URL
		vars := mux.Vars(r)
		id := vars["id"]

		// Get the "tables" collection from the database
		collection := client.Database(Database).Collection("tables")

		// Convert the ID string to an ObjectId
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Define a filter to find the table with the given ID
		filter := bson.M{"_id": objID}

		// Delete the table matching the filter
		result, err := collection.DeleteOne(context.TODO(), filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if any document was deleted
		if result.DeletedCount == 0 {
			http.Error(w, "Table not found", http.StatusNotFound)
			return
		}

		// Write a success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Table deleted successfully"))
	}
}

// getTables
func getTables(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the "tables" collection from the database
		ctx := context.Background()
		collection := client.Database(Database).Collection("tables")

		// Define an empty filter to retrieve all documents
		filter := bson.M{}

		// Execute the find operation and get the result as a cursor
		cur, err := collection.Find(ctx, filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cur.Close(ctx)

		// Iterate through the cursor and decode each document as a Tables struct
		var tables []TablesGet
		for cur.Next(ctx) {
			var table TablesGet
			err := cur.Decode(&table)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tables = append(tables, table)
		}

		// Encode the result as JSON and write it to the response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tables)
	}
}

// searchItems retrieves all items from the "items" collection in MongoDB that match a search key
func searchItems(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the search key parameter from the request URL
		vars := mux.Vars(r)
		key := vars["key"]

		// Search for items in the "items" collection in MongoDB that match the search key
		collection := client.Database(Database).Collection("products")
		cursor, err := collection.Find(context.Background(), bson.M{"name": primitive.Regex{Pattern: key, Options: "i"}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		// Decode the cursor results into a slice of Item structs
		var items []Item
		for cursor.Next(context.Background()) {
			var item Item
			err := cursor.Decode(&item)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			items = append(items, item)
		}

		// Send the list of matching items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
