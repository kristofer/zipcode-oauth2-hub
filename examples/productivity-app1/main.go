package main

import (
    "context"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/zipcodewilmington/oauth2-hub/pkg/client"
)

var (
    ssoClient     *client.ZipSSOClient
    pkceChallenge *client.PKCEChallenge
)

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Productivity App - Student Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: 0 auto;
        }
        .user-info {
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .assignments {
            margin-top: 20px;
        }
        .assignment {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .button:hover {
            background-color: #0056b3;
        }
        .logout {
            background-color: #dc3545;
        }
        .logout:hover {
            background-color: #c82333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ZipCode Wilmington - Student Portal</h1>
        
        {{if .User}}
            <div class="user-info">
                <h2>Welcome, {{.User.Name}}!</h2>
                <p><strong>Username:</strong> {{.User.PreferredUsername}}</p>
                <p><strong>Email:</strong> {{.User.Email}}</p>
                <p><strong>Cohort:</strong> {{.User.CohortID}}</p>
                <p><strong>Roles:</strong> {{range .User.Roles}}{{.}} {{end}}</p>
            </div>
            
            <div class="assignments">
                <h3>Your Assignments</h3>
                {{range .Assignments}}
                    <div class="assignment">
                        <h4>{{.Title}}</h4>
                        <p>Due: {{.DueDate}}</p>
                        <p>Status: {{.Status}}</p>
                    </div>
                {{else}}
                    <p>No assignments found.</p>
                {{end}}
            </div>
            
            <br>
            <a href="/logout" class="button logout">Logout</a>
        {{else}}
            <p>Please log in to access your student portal.</p>
            <a href="/login" class="button">Login with ZipCode SSO</a>
        {{end}}
    </div>
</body>
</html>
`

type PageData struct {
    User        *client.UserInfo
    Assignments []Assignment
}

type Assignment struct {
    Title   string
    DueDate string
    Status  string
}

func main() {
    // Initialize OAuth2 client
    authServerURL := os.Getenv("KEYCLOAK_URL")
    if authServerURL == "" {
        authServerURL = "http://localhost:8080/realms/zipcodewilmington"
    }
    
    clientID := os.Getenv("CLIENT_ID")
    if clientID == "" {
        clientID = "productivity-app-frontend"
    }
    
    redirectURI := os.Getenv("REDIRECT_URI")
    if redirectURI == "" {
        redirectURI = "http://localhost:3000/callback"
    }
    
    ssoClient = client.NewZipSSOClient(authServerURL, clientID, "", redirectURI)
    
    // Setup routes
    r := gin.Default()
    
    // Parse HTML template
    tmpl := template.Must(template.New("index").Parse(htmlTemplate))
    
    // Session middleware (simplified - use proper session management in production)
    r.Use(func(c *gin.Context) {
        c.Set("template", tmpl)
        c.Next()
    })
    
    // Routes
    r.GET("/", handleHome)
    r.GET("/login", handleLogin)
    r.GET("/callback", handleCallback)
    r.GET("/logout", handleLogout)
    r.GET("/api/assignments", handleGetAssignments)
    
    port := os.Getenv("APP_PORT")
    if port == "" {
        port = "3000"
    }
    
    log.Printf("Starting Productivity App on port %s", port)
    r.Run(":" + port)
}

func handleHome(c *gin.Context) {
    tmpl := c.MustGet("template").(*template.Template)
    
    // Check if user is logged in (simplified - use proper session management)
    tokenCookie, err := c.Cookie("access_token")
    if err != nil || tokenCookie == "" {
        c.Header("Content-Type", "text/html")
        tmpl.Execute(c.Writer, PageData{})
        return
    }
    
    // Get user info
    userInfo, err := ssoClient.GetUserInfo(context.Background(), tokenCookie)
    if err != nil {
        c.SetCookie("access_token", "", -1, "/", "", false, true)
        c.Redirect(http.StatusTemporaryRedirect, "/")
        return
    }
    
    // Mock assignments (in real app, fetch from API)
    assignments := []Assignment{
        {Title: "OAuth2 Implementation Project", DueDate: "2024-12-15", Status: "In Progress"},
        {Title: "Microservices Architecture Quiz", DueDate: "2024-12-10", Status: "Not Started"},
        {Title: "Go Concurrency Patterns", DueDate: "2024-12-20", Status: "Completed"},
    }
    
    c.Header("Content-Type", "text/html")
    tmpl.Execute(c.Writer, PageData{
        User:        userInfo,
        Assignments: assignments,
    })
}

func handleLogin(c *gin.Context) {
    // Generate PKCE challenge
    var err error
    pkceChallenge, err = ssoClient.GeneratePKCE()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate PKCE"})
        return
    }
    
    // Generate random state (simplified - use secure random in production)
    state := "random-state-123"
    c.SetCookie("oauth_state", state, 600, "/", "", false, true)
    
    // Redirect to auth server
    authURL := ssoClient.GetAuthURL(state, pkceChallenge, []string{"openid", "profile", "email"})
    c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func handleCallback(c *gin.Context) {
    // Verify state
    state := c.Query("state")
    stateCookie, _ := c.Cookie("oauth_state")
    if state != stateCookie {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
        return
    }
    
    // Get authorization code
    code := c.Query("code")
    if code == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization code"})
        return
    }
    
    // Exchange code for tokens
    tokens, err := ssoClient.ExchangeCode(context.Background(), code, pkceChallenge)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token exchange failed"})
        return
    }
    
    // Store tokens (simplified - use secure storage in production)
    c.SetCookie("access_token", tokens.AccessToken, tokens.ExpiresIn, "/", "", false, true)
    c.SetCookie("refresh_token", tokens.RefreshToken, 86400*30, "/", "", false, true)
    c.SetCookie("id_token", tokens.IDToken, tokens.ExpiresIn, "/", "", false, true)
    
    // Clear state cookie
    c.SetCookie("oauth_state", "", -1, "/", "", false, true)
    
    // Redirect to home
    c.Redirect(http.StatusTemporaryRedirect, "/")
}

func handleLogout(c *gin.Context) {
    // Get ID token for logout
    idToken, _ := c.Cookie("id_token")
    
    // Clear cookies
    c.SetCookie("access_token", "", -1, "/", "", false, true)
    c.SetCookie("refresh_token", "", -1, "/", "", false, true)
    c.SetCookie("id_token", "", -1, "/", "", false, true)
    
    // Redirect to Keycloak logout
    logoutURL := ssoClient.Logout(context.Background(), idToken, "http://localhost:3000")
    c.Redirect(http.StatusTemporaryRedirect, logoutURL)
}

func handleGetAssignments(c *gin.Context) {
    // Check authentication
    tokenCookie, err := c.Cookie("access_token")
    if err != nil || tokenCookie == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
        return
    }
    
    // In a real app, this would call the resource server with the access token
    // For now, return mock data
    assignments := []Assignment{
        {Title: "OAuth2 Implementation Project", DueDate: "2024-12-15", Status: "In Progress"},
        {Title: "Microservices Architecture Quiz", DueDate: "2024-12-10", Status: "Not Started"},
    }
    
    c.JSON(http.StatusOK, assignments)
}
