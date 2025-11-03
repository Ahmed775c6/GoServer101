// main.go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"
)

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
    Remember bool   `json:"rememberMe"`
}

type LoginResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message"`
    UserID  int    `json:"userId,omitempty"`
    Token   string `json:"token,omitempty"`
}

func main() {
    // Define routes
    http.HandleFunc("/api/login", corsMiddleware(loginHandler))
    http.HandleFunc("/api/health", healthHandler)
    http.HandleFunc("/api/external-data", externalDataHandler)
      http.HandleFunc("/", rootHandler) // Example external API

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

    // Simple authentication logic
    if loginReq.Email == "test@example.com" && loginReq.Password == "password" {
        response := LoginResponse{
            Success: true,
            Message: "Login successful!",
            UserID:  123,
            Token:   "go-jwt-token-" + fmt.Sprintf("%d", time.Now().Unix()),
        }
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(response)
    } else {
        response := LoginResponse{
            Success: false,
            Message: "Invalid email or password",
        }
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(response)
    }
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"status": "healthy", "service": "Go API", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
}

func externalDataHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    
    // Example external API integration
    externalData := map[string]interface{}{
        "data": "This came from Go server external API",
        "timestamp": time.Now().Unix(),
        "source": "external_service",
    }
    
    json.NewEncoder(w).Encode(externalData)
}
func rootHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintln(w, "Hello, world! Welcome to vesto.cloud")
}