import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")

    # AWS S3 Configuration
    S3_BUCKET = "my-flask-upload-buckets-25-26"
    S3_ACCESS_KEY = "AKIA2NNTTSYMPZ4MBT4E"
    S3_SECRET_KEY = "STd9oKD25xIxYGMJ3MrWOafNkEmn/DIYWYoQwg7o"
    S3_REGION = "eu-north-1"
