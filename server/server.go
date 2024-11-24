package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"` // In practice, store hashed passwords
}

type Tenant struct {
	ID        string   `json:id`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
}

type JwtClaims struct {
	Role      string   `json:"role,omitempty"`
	UserID    string   `json:"userID"`
	Endpoints []string `json:"endpoints,omitempty"`
	jwt.StandardClaims
}

type Endpoints struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
	URL string `json:"url"`
}

type ProxyHandler struct {
	db *sql.DB
}

type rowEndpoints []Endpoints

func main() {
	r := gin.Default()

	// Connect to local SQLlite database
	db, err := sql.Open("sqlite3", "./proxy.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Creates tables if not existed
	setupDatabase(db)

	r.POST("/login", loginHandler(db))

	protectedRoutes := r.Group("/admin", authMiddleware(), authorizeEndpointMiddleware())
	{
		protectedRoutes.POST("/create-tenant-token", createTenantTokenHandler(db))
		protectedRoutes.POST("/revoke-tenant-token", revokeTenantTokenHandler(db))
		protectedRoutes.GET("/get-tenant-token", getTenantTokenHandler(db))

		// Endpoint related routes

		protectedRoutes.POST("/endpoint", createKeyUrlHandler(db))
		protectedRoutes.GET("/endpoint/:path", readKeyUrlHandler(db))
		protectedRoutes.GET("/endpoints", getAllKeyUrlHandler(db))
		protectedRoutes.PUT("/endpoint/:path", updateKeyUrlHandler(db))
		protectedRoutes.DELETE("/endpoint/:path", deleteKeyUrlHandler(db))
	}

	// Setup proxy handler
	proxyHandler := NewProxyHandler(db)

	// Proxy route
	r.GET("/proxy/:key", authMiddleware(), authorizeEndpointMiddleware(), proxyHandler.Proxy)

	r.Run() // listen and serve on 0.0.0.0:8080
}

func NewProxyHandler(db *sql.DB) *ProxyHandler {
	return &ProxyHandler{db: db}
}

func (ph *ProxyHandler) Proxy(c *gin.Context) {
	key := c.Param("key")
	var savedUrl string
	err := ph.db.QueryRow("SELECT url FROM endpoints WHERE path = ?", key).Scan(&savedUrl)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "No URL found for this key"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	fmt.Println(savedUrl, "Saved URL")

	// Parse the URL to ensure it's valid
	target, err := url.Parse(savedUrl)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid URL in database"})
		return
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Modify the headers, Host is important for the target to respond correctly
	proxy.Director = func(r *http.Request) {
		r.Host = target.Host
		r.URL.Host = target.Host
		r.URL.Scheme = target.Scheme
		r.URL.Path = target.Path

		// Reset the URL path to the original path, ensuring the query and fragment are preserved

		fmt.Println(string(target.Host), r.URL.Path, target.Path)
	}

	// Serve the request through the proxy
	proxy.ServeHTTP(c.Writer, c.Request)
}

func setupDatabase(db *sql.DB) {
	// Create users table
	db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)")

	// Create tokens table
	db.Exec("CREATE TABLE IF NOT EXISTS tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, name TEXT, endpoints TEXT)")

	db.Exec(`CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT UNIQUE NOT NULL,
        url TEXT NOT NULL
    )`)

	var admin User
	admin.Email = "admin@admin.com"
	admin.Password = "9OCodma718g="

	var existingUser User
	err := db.QueryRow("SELECT email, password FROM users WHERE email = ?", admin.Email).Scan(&existingUser.Email, &existingUser.Password)

	switch {
	case err == sql.ErrNoRows:
		// User does not exist, proceed to create the user
		hashedPassword, err := hashPassword(admin.Password)
		if err != nil {
			log.Fatal("Error hashing password: ", err)
		}

		// Prepare the SQL statement with placeholders
		stmt, err := db.Prepare("INSERT INTO users (email, password) VALUES (?, ?)")
		if err != nil {
			log.Fatal("Error preparing statement: ", err)
		}
		defer stmt.Close()

		// Execute the SQL statement with parameters
		_, err = stmt.Exec(admin.Email, hashedPassword)
		if err != nil {
			log.Fatal("Error executing insert: ", err)
		}

		log.Println("Admin user inserted successfully")
	case err != nil:
		// Some database error occurred
		log.Fatal("Database error: ", err)
	default:
		// User already exists
		log.Println("Admin user already exists in the database")
	}

	log.Println("User inserted successfully")

}

func loginHandler(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var u User
		// take email and password form the request body
		if err := ctx.ShouldBindJSON(&u); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var storedUser User
		err := db.QueryRow("SELECT email,password from users WHERE email = ? ", u.Email).Scan(&storedUser.Email, &storedUser.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
				return
			}
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
			return
		}
		fmt.Println(storedUser, "Stored User")
		fmt.Println(u.Password, "Body User")

		// Hash the provided password for comparison
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(u.Password)); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := generateToken(u.Email)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation error"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"token": token})

	}

}

func createTenantTokenHandler(db *sql.DB) gin.HandlerFunc {

	/**
	1. Read from the body
	2. do an upsert/update/save such that if the key already exists just update it or create new.
	3. return the key
	*/

	return func(ctx *gin.Context) {
		var tenant Tenant

		if err := ctx.ShouldBindJSON(&tenant); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Serialize endpoints to string for storage
		endpointsStr := strings.Join(tenant.Endpoints, ",")

		var isExist bool

		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM tenants WHERE email = ?)", tenant.Email).Scan(&isExist)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
			fmt.Println(err, "first error")
			return
		}

		if !isExist {

			result, err := db.Exec("INSERT into tenants (email,name,endpoints) VALUES (?,?,?)", tenant.Email, tenant.Name, endpointsStr)

			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
				fmt.Println(err, "second error")
				return
			}

			id, _ := result.LastInsertId()
			token, err := generateTenantToken(tenant.Email, tenant.Endpoints)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation error"})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"id": id, "token": token})
			return
		}

		// Tenant exists, update endpoints
		_, err = db.Exec("UPDATE tenants SET endpoints = ? WHERE email = ?", endpointsStr, tenant.Email)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant endpoints"})
			return
		}

		// Generate and return the updated token
		token, err := generateTenantToken(tenant.Email, tenant.Endpoints)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation error"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Tenant endpoints updated", "token": token})
	}

}

func revokeTenantTokenHandler(db *sql.DB) gin.HandlerFunc {

	/**
	1. Read from the body
	2. do an upsert/update/save such that if the key already exists just update it or create new.
	3. return the key
	*/

	return func(ctx *gin.Context) {

	}

}

// Function to hash a password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) // 14 is the cost
	return string(bytes), err
}

func generateToken(email string) (string, error) {

	claims := &JwtClaims{
		Role:   "admin",
		UserID: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte("pBv8V++jEjZviBH0J+6zu5Jgg25A2saB/M3FApn50cY=")) // Use a proper secret key in production
}

func generateTenantToken(email string, endpoints []string) (string, error) {
	claims := &JwtClaims{
		UserID:    email,
		Endpoints: endpoints,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("pBv8V++jEjZviBH0J+6zu5Jgg25A2saB/M3FApn50cY="))
}

func getTenantTokenHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.Query("email")
		if email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
			return
		}

		var tenant Tenant
		var endpointsStr string
		err := db.QueryRow("SELECT id, email, name, endpoints FROM tenants WHERE email = ?", email).Scan(&tenant.ID, &tenant.Email, &tenant.Name, &endpointsStr)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
				fmt.Println(err, "Errors")
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
			}
			return
		}

		tenant.Endpoints = strings.Split(endpointsStr, ",")
		token, err := generateTenantToken(tenant.Email, tenant.Endpoints)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"tenant": tenant, "token": token})
	}
}

// Endpoint Related Code here

func createKeyUrlHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var keyUrl Endpoints
		if err := c.ShouldBindJSON(&keyUrl); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := db.Exec("INSERT INTO endpoints (path, url) VALUES (?, ?)", keyUrl.Key, keyUrl.URL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert key-url pair"})
			fmt.Println(err)
			return
		}

		id, _ := result.LastInsertId()
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Key-URL pair created successfully", "key": keyUrl.Key, "url": keyUrl.URL})
	}
}

// Read operation (for a specific key)
func readKeyUrlHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Param("path")
		var keyUrl Endpoints
		err := db.QueryRow("SELECT id, path, url FROM endpoints WHERE path = ?", path).Scan(&keyUrl.ID, &keyUrl.Key, &keyUrl.URL)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "path not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}

		c.JSON(http.StatusOK, keyUrl)
	}
}

// Read operation (for a specific key)
func getAllKeyUrlHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query("SELECT id, path, url FROM endpoints")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database query error"})
			return
		}
		defer rows.Close()
		var rowEndpoints = rowEndpoints{}
		for rows.Next() {
			var endpoint Endpoints
			err := rows.Scan(&endpoint.ID, &endpoint.Key, &endpoint.URL)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning rows"})
				return
			}
			rowEndpoints = append(rowEndpoints, endpoint)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error iterating over rows"})
			return
		}

		// If no endpoints were found, return an empty list instead of an error
		if len(rowEndpoints) == 0 {
			c.JSON(http.StatusOK, gin.H{"endpoints": []Endpoints{}})
		} else {
			c.JSON(http.StatusOK, gin.H{"endpoints": rowEndpoints})
		}
	}
}

// Update operation
func updateKeyUrlHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.Param("path")
		var keyUrl Endpoints
		if err := c.ShouldBindJSON(&keyUrl); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := db.Exec("UPDATE endpoints SET url = ? WHERE path = ?", keyUrl.URL, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update URL"})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "path not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "path-URL pair updated successfully"})
	}
}

// Delete operation
func deleteKeyUrlHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.Param("path")
		result, err := db.Exec("DELETE FROM endpoints WHERE path = ?", key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete key-url pair"})
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "path not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "path-URL pair deleted successfully"})
	}
}

// Middlewares

// Auth Middleware
func authMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := ctx.GetHeader("authorization")
		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			ctx.Abort()
			return
		}
		// Expected format: "Bearer <token>"
		parts := strings.SplitN(tokenString, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			ctx.Abort()
			return
		}

		tokenString = parts[1]

		token, _ := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("pBv8V++jEjZviBH0J+6zu5Jgg25A2saB/M3FApn50cY="), nil // replace with your key
		})

		if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
			ctx.Set("claims", claims)
			ctx.Next()
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			ctx.Abort()
		}
	}
}

func authorizeEndpointMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing claims in context"})
			c.Abort()
			return
		}

		jwtClaims, ok := claims.(*JwtClaims)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cast claims"})
			c.Abort()
			return
		}

		if jwtClaims.Role == "admin" {
			return
		}
		path := c.Request.URL.Path
		for _, endpoint := range jwtClaims.Endpoints {
			if endpoint == path {
				c.Next() // User has permission to access this endpoint
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have access to this endpoint"})
		c.Abort()
	}
}
