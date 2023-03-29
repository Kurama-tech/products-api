package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Item struct {
	Name  string `json:"name"`
	Price int    `json:"price"`
	Description string `json:"description"`
	TableAttached []string `json:"tables"`

}

type TableData struct {
	Name string `json:"name"`
}

type Table struct{
	Name string `json:"name"`
	Description string `json:"description"`
	TableHeadings []TableData `json:"tableheading"`
	TableData []TableData `json:"tabledata"`
}

const Database = "jwc"

func main() {
	// MongoDB client options

	// Get the value of the "ENV_VAR_NAME" environment variable
	mongoURL := os.Getenv("MONGO_URL")
	
	// Check if the environment variable is set
	if mongoURL == "" {
		fmt.Println("MongoDB Environment variable is not set")
		os.Exit(1)
	} else {
		fmt.Printf("MongoDB Environment variable value is: %s\n", mongoURL)
	}
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
	
	// Create a new router using Gorilla Mux
	router := mux.NewRouter()
	
	// Define a POST route to add an item to a collection
	router.HandleFunc("/items", addItem(client)).Methods("POST")

	router.HandleFunc("/items", getItems(client)).Methods("GET")
	
	// Define a DELETE route to delete an item from a collection
	router.HandleFunc("/items/{name}", deleteItem(client)).Methods("DELETE")
	
	// Define a PUT route to edit an item in a collection
	router.HandleFunc("/items/{name}", editItem(client)).Methods("PUT")
	
	// Start the HTTP server
	log.Println("Starting HTTP server...")
	err = http.ListenAndServe(":8002", router)
	if err != nil {
		log.Fatal(err)
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

// deleteItem deletes an item from the "items" collection in MongoDB
func deleteItem(client *mongo.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the name parameter from the request URL
		vars := mux.Vars(r)
		name := vars["name"]
		
		// Delete the item from the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		_, err := collection.DeleteOne(context.Background(), bson.M{"name": name})
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
		name := vars["name"]
		
		// Parse the request body into an Item struct
		var item Item
		err := json.NewDecoder(r.Body).Decode(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		tables := item.TableAttached
		
		// Update the item in the "items" collection in MongoDB
		collection := client.Database(Database).Collection("products")
		filter := bson.M{"name": name}
		update := bson.M{"$set": bson.M{"price": item.Price, "name": item.Name, "description":item.Description }}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i:=0; i<len(tables);i++{
			filter := bson.M{"name": item.Name}
			update:= bson.M{"$addToSet": bson.M{"tables": tables[i]}}
			_, err = collection.UpdateOne(context.Background(), filter, update)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
		
		// Send the list of items as a JSON response
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
