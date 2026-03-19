// Intentionally vulnerable: sensitive data in console.log
function authenticate(token) {
    console.log("Auth token:", token);
    console.log("password:", userPassword);
    console.log("api_key:", apiKey);
    console.log("secret:", clientSecret);
}
