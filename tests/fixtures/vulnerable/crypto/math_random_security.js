// Intentionally vulnerable: Math.random for security
function generateToken() {
    return Math.random().toString(36).substring(2);
}
function generateSessionId() {
    return Math.random().toString(16).slice(2);
}
