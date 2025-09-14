from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from extensions import db
from config import Config
import joblib
import globals as app_globals

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

jwt = JWTManager(app)
swagger = Swagger(app)

import models
from routes import bp
app.register_blueprint(bp)

# Initialize database and load model within application context
with app.app_context():
    db.create_all()
    model = joblib.load('iris_model.pkl')
    app_globals.initialize_model(model)

if __name__ == '__main__':
    app.run(debug=True)

