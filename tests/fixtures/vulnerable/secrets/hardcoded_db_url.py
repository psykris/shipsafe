# Intentionally vulnerable: database URL with credentials
DATABASE_URL = "postgres://admin:supersecret@db.example.com:5432/myapp"
MONGO_URI = "mongodb://root:password123@mongo.example.com:27017/admin"
REDIS_URL = "redis://:mysecretpassword@redis.example.com:6379/0"
