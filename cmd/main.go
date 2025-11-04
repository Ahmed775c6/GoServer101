// main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name     string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
	Password string             `json:"password,omitempty" bson:"password"`
	Company  string             `json:"company" bson:"company"`
	Plan     string             `json:"plan" bson:"plan"`
	CreatedAt time.Time         `json:"createdAt" bson:"createdAt"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"rememberMe"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	UserID  string `json:"userId,omitempty"`
	Token   string `json:"token,omitempty"`
	User    *User  `json:"user,omitempty"`
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Company  string `json:"company"`
}

var mongoClient *mongo.Client
var userCollection *mongo.Collection

func main() {
	// MongoDB setup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var err error
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("MongoDB connection error: ", err)
	}
	
	// Verify connection
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		log.Fatal("MongoDB ping error: ", err)
	}
	
	fmt.Println("Connected to MongoDB successfully!")
	
	userCollection = mongoClient.Database("VestoDB").Collection("users")
	
	// Create unique index on email
	indexModel := mongo.IndexModel{
		Keys:    bson.M{"email": 1},
		Options: options.Index().SetUnique(true),
	}
	_, err = userCollection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		log.Println("Warning: Could not create unique index on email:", err)
	}

	// Define routes
	http.HandleFunc("/api/register", corsMiddleware(registerHandler))
	http.HandleFunc("/api/login", corsMiddleware(loginHandler))
	http.HandleFunc("/api/health", corsMiddleware(healthHandler))
	http.HandleFunc("/api/external-data", corsMiddleware(externalDataHandler))
	http.HandleFunc("/api/validate-token", corsMiddleware(validateTokenHandler))
	http.HandleFunc("/api/user/", corsMiddleware(getUserHandler)) // Note the trailing slash
	http.HandleFunc("/", corsMiddleware(rootHandler))

	port := ":8080"
	fmt.Printf("Go API server starting on http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    
    if r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "Method not allowed",
        })
        return
    }

    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "Invalid request body",
        })
        return
    }

    // Validate required fields
    if req.Name == "" || req.Email == "" || req.Password == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "Name, email, and password are required",
        })
        return
    }

    // Check if user already exists
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    var existingUser User
    err := userCollection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&existingUser)
    if err == nil {
        w.WriteHeader(http.StatusConflict)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "User with this email already exists",
        })
        return
    }

    // Hash password
    hashedPassword, err := hashPassword(req.Password)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "Error processing password",
        })
        return
    }

    // Create new user
    newUser := User{
        Name:      req.Name,
        Email:     req.Email,
        Password:  hashedPassword,
        Company:   req.Company,
        Plan:      "Essential",
        CreatedAt: time.Now(),
    }

    result, err := userCollection.InsertOne(ctx, newUser)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "message": "Failed to create user",
        })
        return
    }

    // Return success response without password
    newUser.Password = ""
    newUser.ID = result.InsertedID.(primitive.ObjectID)
    
    response := map[string]interface{}{
        "success": true,
        "message": "User registered successfully",
        "user":    newUser,
        "token":   fmt.Sprintf("go-jwt-token-%s-%d", newUser.ID.Hex(), time.Now().Unix()),
    }
    
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(response)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != "POST" {
		http.Error(w, `{"success": false, "message": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var loginReq LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, `{"success": false, "message": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Find user by email
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var user User
	err = userCollection.FindOne(ctx, bson.M{"email": loginReq.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			response := LoginResponse{
				Success: false,
				Message: "Invalid email or password",
			}
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}
		http.Error(w, `{"success": false, "message": "Database error"}`, http.StatusInternalServerError)
		return
	}

	// Check password
	if !checkPasswordHash(loginReq.Password, user.Password) {
		response := LoginResponse{
			Success: false,
			Message: "Invalid email or password",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate token (in a real application, use JWT or similar)
	token := fmt.Sprintf("go-jwt-token-%s-%d", user.ID.Hex(), time.Now().Unix())

	// Remove password from user object before sending response
	user.Password = ""

	response := LoginResponse{
		Success: true,
		Message: "Login successful!",
		UserID:  user.ID.Hex(),
		Token:   token,
		User:    &user,
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Check MongoDB connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	dbStatus := "connected"
	err := mongoClient.Ping(ctx, nil)
	if err != nil {
		dbStatus = "disconnected"
	}
	
	healthData := map[string]interface{}{
		"status":    "healthy",
		"service":   "Go API",
		"timestamp": time.Now().Format(time.RFC3339),
		"database":  dbStatus,
	}
	
	json.NewEncoder(w).Encode(healthData)
}

func externalDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Example external API integration
	externalData := map[string]interface{}{
		"data":      "This came from Go server external API",
		"timestamp": time.Now().Unix(),
		"source":    "external_service",
	}
	
	json.NewEncoder(w).Encode(externalData)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Hello, world! Welcome to vesto.cloud")
}
// Add this struct
type UserResponse struct {
	Success bool  `json:"success"`
	User    *User `json:"user,omitempty"`
	Message string `json:"message,omitempty"`
}

// Add this handler function
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Extract user ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(UserResponse{
			Success: false,
			Message: "Invalid user ID",
		})
		return
	}
	
	userID := pathParts[3]
	
	// Validate user ID
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(UserResponse{
			Success: false,
			Message: "Invalid user ID format",
		})
		return
	}
	
	// Find user by ID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var user User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(UserResponse{
				Success: false,
				Message: "User not found",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(UserResponse{
			Success: false,
			Message: "Database error",
		})
		return
	}
	
	// Remove password before sending
	user.Password = ""
	
	response := UserResponse{
		Success: true,
		User:    &user,
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Add token validation endpoint
func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "No authorization token",
		})
		return
	}
	
	// Simple token validation (in production, use proper JWT validation)
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if !strings.HasPrefix(token, "go-jwt-token-") {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid token format",
		})
		return
	}
	
	// Extract user ID from token
	parts := strings.Split(token, "-")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid token",
		})
		return
	}
	
	userID := parts[3]
	
	// Validate user exists
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid user in token",
		})
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	var user User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "User not found",
		})
		return
	}
	
	// Token is valid
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Token is valid",
		"user_id": userID,
	})
}
