class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///mydatabase.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'your_jwt_secret_key'
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_DELTA = 3600

    SECRET_KEY = 'superchavesecreta'
    CACHE_TYPE = 'simple'
    SWAGGER = {
        'title': 'First MachineLearning Project from FIAP',
        'uiversion': 3
    }
