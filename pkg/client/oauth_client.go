package client

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// ZipSSOClient provides OAuth2 client functionality
type ZipSSOClient struct {
    authServerURL string
    clientID      string
    clientSecret  string
    redirectURI   string
    httpClient    *http.Client
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    IDToken      string `json:"id_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
}

// UserInfo represents user information from the ID token
type UserInfo struct {
    Subject           string   `json:"sub"`
    Name              string   `json:"name"`
    PreferredUsername string   `json:"preferred_username"`
    Email             string   `json:"email"`
    EmailVerified     bool     `json:"email_verified"`
    Roles             []string `json:"roles"`
    CohortID          string   `json:"cohortId"`
}

// PKCEChallenge represents PKCE challenge parameters
type PKCEChallenge struct {
    CodeVerifier string
    CodeChallenge string
}

// NewZipSSOClient creates a new OAuth2 client
func NewZipSSOClient(authServerURL, clientID, clientSecret, redirectURI string) *ZipSSOClient {
    return &ZipSSOClient{
        authServerURL: authServerURL,
        clientID:      clientID,
        clientSecret:  clientSecret,
        redirectURI:   redirectURI,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// GeneratePKCE creates a new PKCE challenge
func (c *ZipSSOClient) GeneratePKCE() (*PKCEChallenge, error) {
    // Generate code verifier
    verifierBytes := make([]byte, 32)
    if _, err := rand.Read(verifierBytes); err != nil {
        return nil, err
    }
    verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
    
    // Generate code challenge
    h := sha256.New()
    h.Write([]byte(verifier))
    challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
    
    return &PKCEChallenge{
        CodeVerifier:  verifier,
        CodeChallenge: challenge,
    }, nil
}

// GetAuthURL returns the authorization URL with PKCE
func (c *ZipSSOClient) GetAuthURL(state string, pkce *PKCEChallenge, scopes []string) string {
    params := url.Values{}
    params.Add("client_id", c.clientID)
    params.Add("response_type", "code")
    params.Add("redirect_uri", c.redirectURI)
    params.Add("state", state)
    params.Add("scope", strings.Join(scopes, " "))
    
    if pkce != nil {
        params.Add("code_challenge", pkce.CodeChallenge)
        params.Add("code_challenge_method", "S256")
    }
    
    return fmt.Sprintf("%s/protocol/openid-connect/auth?%s", 
        c.authServerURL, params.Encode())
}

// ExchangeCode exchanges authorization code for tokens
func (c *ZipSSOClient) ExchangeCode(ctx context.Context, code string, pkce *PKCEChallenge) (*TokenResponse, error) {
    tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", c.authServerURL)
    
    data := url.Values{}
    data.Set("grant_type", "authorization_code")
    data.Set("client_id", c.clientID)
    data.Set("code", code)
    data.Set("redirect_uri", c.redirectURI)
    
    if c.clientSecret != "" {
        data.Set("client_secret", c.clientSecret)
    }
    
    if pkce != nil {
        data.Set("code_verifier", pkce.CodeVerifier)
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token exchange failed: %s", string(body))
    }
    
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    
    return &tokenResp, nil
}

// RefreshToken refreshes an access token
func (c *ZipSSOClient) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
    tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", c.authServerURL)
    
    data := url.Values{}
    data.Set("grant_type", "refresh_token")
    data.Set("client_id", c.clientID)
    data.Set("refresh_token", refreshToken)
    
    if c.clientSecret != "" {
        data.Set("client_secret", c.clientSecret)
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token refresh failed: %s", string(body))
    }
    
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    
    return &tokenResp, nil
}

// GetUserInfo retrieves user information from the userinfo endpoint
func (c *ZipSSOClient) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
    userInfoURL := fmt.Sprintf("%s/protocol/openid-connect/userinfo", c.authServerURL)
    
    req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+accessToken)
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("userinfo request failed: %s", string(body))
    }
    
    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }
    
    return &userInfo, nil
}

// Logout performs a logout operation
func (c *ZipSSOClient) Logout(ctx context.Context, idToken, redirectURI string) string {
    logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout", c.authServerURL)
    
    params := url.Values{}
    params.Add("id_token_hint", idToken)
    
    if redirectURI != "" {
        params.Add("post_logout_redirect_uri", redirectURI)
    }
    
    return fmt.Sprintf("%s?%s", logoutURL, params.Encode())
}

// IntrospectToken validates a token and returns its metadata
func (c *ZipSSOClient) IntrospectToken(ctx context.Context, token string) (map[string]interface{}, error) {
    introspectURL := fmt.Sprintf("%s/protocol/openid-connect/token/introspect", c.authServerURL)
    
    data := url.Values{}
    data.Set("token", token)
    data.Set("client_id", c.clientID)
    
    if c.clientSecret != "" {
        data.Set("client_secret", c.clientSecret)
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return result, nil
}

// ClientCredentials performs client credentials flow for service-to-service auth
func (c *ZipSSOClient) ClientCredentials(ctx context.Context, scopes []string) (*TokenResponse, error) {
    if c.clientSecret == "" {
        return nil, fmt.Errorf("client secret required for client credentials flow")
    }
    
    tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", c.authServerURL)
    
    data := url.Values{}
    data.Set("grant_type", "client_credentials")
    data.Set("client_id", c.clientID)
    data.Set("client_secret", c.clientSecret)
    
    if len(scopes) > 0 {
        data.Set("scope", strings.Join(scopes, " "))
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("client credentials failed: %s", string(body))
    }
    
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    
    return &tokenResp, nil
}
