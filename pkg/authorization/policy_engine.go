package authorization

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/redis/go-redis/v9"
)

// PolicyEngine handles authorization decisions
type PolicyEngine struct {
    keycloakURL  string
    clientID     string
    clientSecret string
    cache        *redis.Client
}

// PolicyRequest represents an authorization request
type PolicyRequest struct {
    Subject    string            `json:"subject"`
    Resource   string            `json:"resource"`
    Action     string            `json:"action"`
    Attributes map[string]string `json:"attributes"`
}

// PolicyDecision represents the authorization decision
type PolicyDecision struct {
    Allowed bool              `json:"allowed"`
    Reason  string            `json:"reason"`
    Context map[string]string `json:"context"`
}

// NewPolicyEngine creates a new policy engine instance
func NewPolicyEngine(keycloakURL, clientID, clientSecret string, cache *redis.Client) *PolicyEngine {
    return &PolicyEngine{
        keycloakURL:  keycloakURL,
        clientID:     clientID,
        clientSecret: clientSecret,
        cache:        cache,
    }
}

// Evaluate makes an authorization decision
func (pe *PolicyEngine) Evaluate(ctx context.Context, request PolicyRequest) (*PolicyDecision, error) {
    // Check cache first
    cacheKey := fmt.Sprintf("policy:%s:%s:%s", request.Subject, request.Resource, request.Action)
    cached, err := pe.cache.Get(ctx, cacheKey).Result()
    if err == nil {
        var decision PolicyDecision
        json.Unmarshal([]byte(cached), &decision)
        return &decision, nil
    }
    
    // Evaluate with custom policies first
    decision := pe.evaluateCustomPolicies(request)
    
    // If custom policies don't provide a definitive answer, check with Keycloak
    if decision == nil {
        decision = pe.evaluateWithKeycloak(request)
    }
    
    // Cache the decision
    if decision != nil {
        decisionJSON, _ := json.Marshal(decision)
        pe.cache.Set(ctx, cacheKey, decisionJSON, 5*time.Minute)
    }
    
    return decision, nil
}

// evaluateCustomPolicies checks against custom policy rules
func (pe *PolicyEngine) evaluateCustomPolicies(request PolicyRequest) *PolicyDecision {
    // Check cohort-based access
    if strings.HasPrefix(request.Resource, "cohort:") {
        return pe.cohortAccessPolicy(request)
    }
    
    // Check time-based access for exams
    if strings.HasPrefix(request.Resource, "exam:") {
        return pe.timeBasedPolicy(request)
    }
    
    // Check submission policies
    if strings.HasPrefix(request.Resource, "submission:") {
        return pe.submissionPolicy(request)
    }
    
    return nil
}

// cohortAccessPolicy ensures users can only access their own cohort resources
func (pe *PolicyEngine) cohortAccessPolicy(request PolicyRequest) *PolicyDecision {
    userCohort := request.Attributes["userCohortId"]
    resourceCohort := request.Attributes["resourceCohortId"]
    
    if userCohort == "" || resourceCohort == "" {
        return &PolicyDecision{
            Allowed: false,
            Reason:  "Missing cohort information",
        }
    }
    
    // Instructors can access any cohort
    if request.Attributes["userRole"] == "instructor" {
        return &PolicyDecision{
            Allowed: true,
            Reason:  "Instructor access granted",
            Context: map[string]string{
                "policy": "instructor-override",
            },
        }
    }
    
    // Students can only access their own cohort
    if userCohort == resourceCohort {
        return &PolicyDecision{
            Allowed: true,
            Reason:  "Cohort match",
            Context: map[string]string{
                "userCohort":     userCohort,
                "resourceCohort": resourceCohort,
            },
        }
    }
    
    return &PolicyDecision{
        Allowed: false,
        Reason:  "Cohort mismatch",
        Context: map[string]string{
            "userCohort":     userCohort,
            "resourceCohort": resourceCohort,
        },
    }
}

// timeBasedPolicy restricts access based on time windows
func (pe *PolicyEngine) timeBasedPolicy(request PolicyRequest) *PolicyDecision {
    resourceType := request.Attributes["resourceType"]
    now := time.Now()
    
    switch resourceType {
    case "exam":
        // Exam access window
        examStartStr := request.Attributes["examStart"]
        examEndStr := request.Attributes["examEnd"]
        
        if examStartStr != "" && examEndStr != "" {
            examStart, _ := time.Parse(time.RFC3339, examStartStr)
            examEnd, _ := time.Parse(time.RFC3339, examEndStr)
            
            if now.After(examStart) && now.Before(examEnd) {
                return &PolicyDecision{
                    Allowed: true,
                    Reason:  "Within exam window",
                    Context: map[string]string{
                        "currentTime": now.Format(time.RFC3339),
                        "examStart":   examStartStr,
                        "examEnd":     examEndStr,
                    },
                }
            }
            
            return &PolicyDecision{
                Allowed: false,
                Reason:  "Outside exam window",
                Context: map[string]string{
                    "currentTime": now.Format(time.RFC3339),
                    "examStart":   examStartStr,
                    "examEnd":     examEndStr,
                },
            }
        }
        
    case "lab":
        // Lab hours: 8 AM to 8 PM
        hour := now.Hour()
        if hour >= 8 && hour <= 20 {
            return &PolicyDecision{
                Allowed: true,
                Reason:  "Within lab hours",
                Context: map[string]string{
                    "currentHour": fmt.Sprintf("%d", hour),
                },
            }
        }
        
        return &PolicyDecision{
            Allowed: false,
            Reason:  "Outside lab hours (8 AM - 8 PM)",
            Context: map[string]string{
                "currentHour": fmt.Sprintf("%d", hour),
            },
        }
    }
    
    return nil
}

// submissionPolicy handles assignment submission rules
func (pe *PolicyEngine) submissionPolicy(request PolicyRequest) *PolicyDecision {
    // Check if assignment is still open for submissions
    deadlineStr := request.Attributes["assignmentDeadline"]
    if deadlineStr != "" {
        deadline, err := time.Parse(time.RFC3339, deadlineStr)
        if err == nil && time.Now().After(deadline) {
            // Check for late submission allowance
            if request.Attributes["allowLateSubmission"] == "true" {
                return &PolicyDecision{
                    Allowed: true,
                    Reason:  "Late submission allowed",
                    Context: map[string]string{
                        "isLate": "true",
                    },
                }
            }
            
            return &PolicyDecision{
                Allowed: false,
                Reason:  "Past submission deadline",
                Context: map[string]string{
                    "deadline": deadlineStr,
                },
            }
        }
    }
    
    // Check submission attempts
    maxAttempts := request.Attributes["maxAttempts"]
    currentAttempts := request.Attributes["currentAttempts"]
    
    if maxAttempts != "" && currentAttempts != "" {
        if currentAttempts >= maxAttempts {
            return &PolicyDecision{
                Allowed: false,
                Reason:  "Maximum submission attempts reached",
                Context: map[string]string{
                    "maxAttempts":     maxAttempts,
                    "currentAttempts": currentAttempts,
                },
            }
        }
    }
    
    return &PolicyDecision{
        Allowed: true,
        Reason:  "Submission allowed",
    }
}

// evaluateWithKeycloak queries Keycloak's authorization services
func (pe *PolicyEngine) evaluateWithKeycloak(request PolicyRequest) *PolicyDecision {
    // This is a simplified version - in production, you'd implement
    // the full UMA 2.0 flow or use Keycloak's authorization client
    
    tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", pe.keycloakURL)
    
    data := map[string]string{
        "grant_type":    "urn:ietf:params:oauth:grant-type:uma-ticket",
        "client_id":     pe.clientID,
        "client_secret": pe.clientSecret,
        "subject_token": request.Subject,
        "resource":      request.Resource,
        "scope":         request.Action,
    }
    
    jsonData, _ := json.Marshal(data)
    resp, err := http.Post(tokenURL, "application/json", bytes.NewBuffer(jsonData))
    
    if err != nil {
        return &PolicyDecision{
            Allowed: false,
            Reason:  "Authorization service error",
        }
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == http.StatusOK {
        return &PolicyDecision{
            Allowed: true,
            Reason:  "Keycloak authorization granted",
        }
    }
    
    return &PolicyDecision{
        Allowed: false,
        Reason:  "Keycloak authorization denied",
    }
}

// ResourceAttributes extracts attributes from a resource identifier
func (pe *PolicyEngine) ResourceAttributes(resourceID string) map[string]string {
    attrs := make(map[string]string)
    
    // Parse resource ID format: "type:id:cohort"
    parts := strings.Split(resourceID, ":")
    if len(parts) >= 2 {
        attrs["resourceType"] = parts[0]
        attrs["resourceId"] = parts[1]
        if len(parts) >= 3 {
            attrs["resourceCohortId"] = parts[2]
        }
    }
    
    return attrs
}
