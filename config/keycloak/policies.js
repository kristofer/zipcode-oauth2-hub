// Cohort-Based Access Policy
// This policy ensures students can only access resources from their cohort

function evaluate() {
    var context = $evaluation.getContext();
    var identity = context.getIdentity();
    var permission = $evaluation.getPermission();
    
    // Check if user has instructor role - they can access any cohort
    if (identity.hasRealmRole('instructor')) {
        $evaluation.grant();
        return;
    }
    
    // For students, check cohort match
    if (identity.hasRealmRole('student')) {
        var attributes = identity.getAttributes();
        var userCohortId = attributes.getValue('cohortId');
        
        if (userCohortId) {
            // Get resource attributes
            var resource = permission.getResource();
            if (resource) {
                var resourceCohortId = resource.getAttribute('cohortId');
                
                // Students can only access their own cohort resources
                if (userCohortId.equals(resourceCohortId)) {
                    $evaluation.grant();
                } else {
                    $evaluation.deny();
                }
            }
        } else {
            // No cohort assigned to user
            $evaluation.deny();
        }
    }
}

evaluate();

// ===================================
// Time-Based Access Policy
// This policy restricts access based on time windows

function evaluateTimeBasedAccess() {
    var context = $evaluation.getContext();
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    
    if (resource) {
        var resourceType = resource.getType();
        var now = new Date();
        var hour = now.getHours();
        
        switch(resourceType) {
            case 'exam':
                // Exams only available 9 AM - 12 PM
                if (hour >= 9 && hour < 12) {
                    $evaluation.grant();
                } else {
                    $evaluation.deny();
                }
                break;
                
            case 'lab':
                // Labs available 8 AM - 8 PM
                if (hour >= 8 && hour < 20) {
                    $evaluation.grant();
                } else {
                    $evaluation.deny();
                }
                break;
                
            case 'assignment':
                // Check deadline if set
                var deadline = resource.getAttribute('deadline');
                if (deadline) {
                    var deadlineDate = new Date(deadline);
                    if (now <= deadlineDate) {
                        $evaluation.grant();
                    } else {
                        // Check if late submissions allowed
                        var allowLate = resource.getAttribute('allowLateSubmission');
                        if (allowLate && allowLate === 'true') {
                            $evaluation.grant();
                        } else {
                            $evaluation.deny();
                        }
                    }
                } else {
                    $evaluation.grant();
                }
                break;
                
            default:
                // No time restrictions for other resources
                $evaluation.grant();
        }
    }
}

evaluateTimeBasedAccess();

// ===================================
// Graduated Student Policy
// This policy gives alumni read-only access to certain resources

function evaluateAlumniAccess() {
    var context = $evaluation.getContext();
    var identity = context.getIdentity();
    var permission = $evaluation.getPermission();
    
    var attributes = identity.getAttributes();
    var graduationDate = attributes.getValue('graduationDate');
    
    if (graduationDate) {
        var gradDate = new Date(graduationDate);
        var now = new Date();
        
        // User has graduated
        if (now > gradDate) {
            var scopes = permission.getScopes();
            
            // Alumni only get read access
            if (scopes && scopes.contains('read')) {
                $evaluation.grant();
            } else {
                $evaluation.deny();
            }
        }
    }
}

evaluateAlumniAccess();

// ===================================
// IP-Based Access Policy
// This policy restricts certain resources to campus network

function evaluateCampusAccess() {
    var context = $evaluation.getContext();
    var attributes = context.getAttributes();
    
    // Get client IP address
    var clientIP = attributes.getValue('kc.client.network.ip_address');
    
    if (clientIP) {
        // Campus network ranges (example)
        var campusRanges = [
            '10.0.0.0/8',
            '192.168.1.0/24'
        ];
        
        // Simple IP check (in production, use proper CIDR matching)
        var isOnCampus = clientIP.startsWith('10.') || 
                         clientIP.startsWith('192.168.1.');
        
        var permission = $evaluation.getPermission();
        var resource = permission.getResource();
        
        if (resource) {
            var requiresCampus = resource.getAttribute('campusOnly');
            
            if (requiresCampus === 'true' && !isOnCampus) {
                $evaluation.deny();
            } else {
                $evaluation.grant();
            }
        }
    }
}

evaluateCampusAccess();

// ===================================
// Submission Attempt Limit Policy
// This policy enforces maximum submission attempts

function evaluateSubmissionAttempts() {
    var context = $evaluation.getContext();
    var identity = context.getIdentity();
    var permission = $evaluation.getPermission();
    var resource = permission.getResource();
    
    if (resource && resource.getType() === 'assignment') {
        var maxAttempts = resource.getAttribute('maxAttempts');
        
        if (maxAttempts) {
            var userId = identity.getId();
            var resourceId = resource.getId();
            
            // In production, this would query a database
            // For demo, we'll use a simple check
            var attemptKey = userId + ':' + resourceId + ':attempts';
            var currentAttempts = context.getAttributes().getValue(attemptKey) || '0';
            
            if (parseInt(currentAttempts) < parseInt(maxAttempts)) {
                $evaluation.grant();
            } else {
                $evaluation.deny();
            }
        } else {
            // No limit set
            $evaluation.grant();
        }
    }
}

evaluateSubmissionAttempts();
