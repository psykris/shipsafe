# PRI002: hardcoded SSN patterns in source code

# SSN in string literal
test_ssn = "123-45-6789"

# SSN in assignment
ssn = "987-65-4321"

# SSN in social_security variable
social_security = "456-78-9012"

# SSN in a dictionary (data at rest)
user_record = {
    "name": "John Doe",
    "ssn": "321-54-9876",
}
