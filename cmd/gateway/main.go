package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "github.com/joho/godotenv"
    "github.com/lestrrat-go/jwx/v2/jwk"
)

type AuthGateway struct {
    jwksURL    string
    jwkSet     jwk.Set
    realmURL   string
}

func NewAuthGateway(realmURL string) (*AuthGateway, error) {
    jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", realmURL)
    
    // Fetch JWKS
    set, err := jwk.Fetch(context.Background(), jwksURL)
    if err != nil {
        return nil, err
    }
    
    return &AuthGateway{
        jwksURL:  jwksURL,
        jwkSet:   set,
        realmURL: realmURL,
    }, nil
}

// ValidateToken middleware for token validation
func (ag *AuthGateway) ValidateToken() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
            c.Abort()
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        
        // Parse and validate token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            kid, ok := token.Header["kid"].(string)
            if !ok {
                return nil, fmt.Errorf("kid header not found")
            }
            
            key, ok := ag.jwkSet.LookupKeyID(kid)
            if !ok {
                return nil, fmt.Errorf("key %s not found", kid)
            }
            
            var pubKey interface{}
            err := key.Raw(&pubKey)
            return pubKey, err
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Extract claims
        claims := token.Claims.(jwt.MapClaims)
        c.Set("user_id", claims["sub"])
        c.Set("email", claims["email"])
        c.Set("preferred_username", claims["preferred_username"])
        
        if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
            if roles, ok := realmAccess["roles"].([]interface{}); ok {
                c.Set("roles", roles)
            }
        }
        
        c.Next()
    }
}

// RequireRole middleware for role-based access control
func (ag *AuthGateway) RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRoles, exists := c.Get("roles")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{"error": "No roles found"})
            c.Abort()
            return
        }
        
        userRolesList := userRoles.([]interface{})
        
        hasRole := false
        for _, requiredRole := range roles {
            for _, userRole := range userRolesList {
                if userRole.(string) == requiredRole {
                    hasRole = true
                    break
                }
            }
        }
        
        if !hasRole {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// GetUserInfo returns user information from the token
func (ag *AuthGateway) GetUserInfo() gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, _ := c.Get("user_id")
        email, _ := c.Get("email")
        username, _ := c.Get("preferred_username")
        roles, _ := c.Get("roles")
        
        c.JSON(http.StatusOK, gin.H{
            "user_id":  userID,
            "email":    email,
            "username": username,
            "roles":    roles,
        })
    }
}

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }
    
    // Get configuration from environment
    keycloakURL := os.Getenv("KEYCLOAK_URL")
    if keycloakURL == "" {
        keycloakURL = "http://localhost:8080"
    }
    
    realmName := os.Getenv("KEYCLOAK_REALM")
    if realmName == "" {
        realmName = "zipcodewilmington"
    }
    
    port := os.Getenv("GATEWAY_PORT")
    if port == "" {
        port = "8081"
    }
    
    // Initialize auth gateway
    realmURL := fmt.Sprintf("%s/realms/%s", keycloakURL, realmName)
    authGateway, err := NewAuthGateway(realmURL)
    if err != nil {
        log.Fatalf("Failed to initialize auth gateway: %v", err)
    }
    
    // Setup Gin router
    r := gin.Default()
    
    // CORS middleware
    r.Use(func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    })
    
    // Public endpoints
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "healthy", "service": "auth-gateway"})
    })
    
    r.GET("/auth/login", func(c *gin.Context) {
        redirectURL := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=productivity-app-frontend&response_type=code&redirect_uri=%s",
            realmURL,
            c.Query("redirect_uri"))
        c.Redirect(http.StatusTemporaryRedirect, redirectURL)
    })
    
    // Protected endpoints
    protected := r.Group("/api")
    protected.Use(authGateway.ValidateToken())
    {
        // User info endpoint
        protected.GET("/user/info", authGateway.GetUserInfo())
        
        // Instructor-only endpoints
        instructorRoutes := protected.Group("/instructor")
        instructorRoutes.Use(authGateway.RequireRole("instructor"))
        {
            instructorRoutes.GET("/cohorts", getCohorts)
            instructorRoutes.POST("/cohorts", createCohort)
            instructorRoutes.GET("/students", getStudents)
        }
        
        // Student endpoints
        studentRoutes := protected.Group("/student")
        studentRoutes.Use(authGateway.RequireRole("student"))
        {
            studentRoutes.GET("/assignments", getAssignments)
            studentRoutes.POST("/submissions", createSubmission)
        }
        
        // Admin endpoints
        adminRoutes := protected.Group("/admin")
        adminRoutes.Use(authGateway.RequireRole("admin"))
        {
            adminRoutes.GET("/users", getAllUsers)
            adminRoutes.PUT("/users/:id", updateUser)
        }
    }
    
    log.Printf("Starting API Gateway on port %s", port)
    r.Run(":" + port)
}

// Handler functions (stubs)
func getCohorts(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"cohorts": []string{"cohort-2024-01", "cohort-2024-02"}})
}

func createCohort(c *gin.Context) {
    c.JSON(http.StatusCreated, gin.H{"message": "Cohort created", "id": "cohort-2024-03"})
}

func getStudents(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"students": []map[string]string{
        {"id": "1", "name": "John Doe", "cohort": "cohort-2024-01"},
        {"id": "2", "name": "Jane Smith", "cohort": "cohort-2024-01"},
    }})
}

func getAssignments(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"assignments": []map[string]string{
        {"id": "1", "title": "OAuth2 Implementation", "due": "2024-12-01"},
    }})
}

func createSubmission(c *gin.Context) {
    c.JSON(http.StatusCreated, gin.H{"message": "Submission created", "id": "sub-123"})
}

func getAllUsers(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"users": []map[string]string{
        {"id": "1", "username": "instructor1", "role": "instructor"},
        {"id": "2", "username": "student1", "role": "student"},
    }})
}

func updateUser(c *gin.Context) {
    userID := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"message": "User updated", "id": userID})
}
