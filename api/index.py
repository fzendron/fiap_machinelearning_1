from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import Swagger
import os
import tempfile
import sqlite3

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # For demo purposes

jwt = JWTManager(app)
swagger = Swagger(app)

# Simple in-memory storage for demo (replace with proper database in production)
users_db = {}
predictions_db = []

def get_db_connection():
    """Create a temporary SQLite database for demo purposes"""
    db_path = os.path.join(tempfile.gettempdir(), 'demo.db')
    conn = sqlite3.connect(db_path)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sepal_length REAL NOT NULL,
            sepal_width REAL NOT NULL,
            petal_length REAL NOT NULL,
            petal_width REAL NOT NULL,
            predicted_class INTEGER NOT NULL
        )
    ''')
    conn.commit()
    return conn

@app.get("/")
def root():
    return jsonify({'message': 'Flask API is working on Vercel!', 'version': '1.0.0'}), 200

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          id: Register
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: The user's email
            password:
              type: string
              description: The user's password
    responses:
      201:
        description: User registered successfully
      400:
        description: Email and password are required
      409:
        description: Email already registered
    """
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    conn = get_db_connection()
    try:
        existing_user = conn.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            return jsonify({'message': 'Email already registered'}), 409
        
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    """
    Login a user
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          id: Login
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: The user's email
            password:
              type: string
              description: The user's password
    responses:
      200:
        description: User logged in successfully
      400:
        description: Email and password are required
      401:
        description: Invalid email or password
    """
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT id, password FROM users WHERE email = ?', (email,)).fetchone()
        if not user or not check_password_hash(user[1], password):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        token = create_access_token(identity=str(user[0]))
        return jsonify({'message': 'User logged in successfully', 'token': token}), 200
    finally:
        conn.close()

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """
    A protected route that requires authentication
    ---
    tags:
      - Protected
    responses:
      200:
        description: Access granted to protected route
    """
    return jsonify({'message': 'Access granted to protected route'}), 200

@app.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    """
    Make a prediction using the Iris model (Demo without ML)
    ---
    tags:
      - Prediction
    parameters:
      - in: body
        name: body
        schema:
          id: Predict
          required:
            - sepal_length
            - sepal_width
            - petal_length
            - petal_width
          properties:
            sepal_length:
              type: number
              format: float
              description: Sepal length of the iris flower
            sepal_width:
              type: number
              format: float
              description: Sepal width of the iris flower
            petal_length:
              type: number
              format: float
              description: Petal length of the iris flower
            petal_width:
              type: number
              format: float
              description: Petal width of the iris flower
    responses:
      200:
        description: Prediction made successfully
      400:
        description: Invalid input data
    """
    data = request.get_json() or {}
    try:
        sepal_length = float(data.get('sepal_length'))
        sepal_width = float(data.get('sepal_width'))
        petal_length = float(data.get('petal_length'))
        petal_width = float(data.get('petal_width'))
    except (TypeError, ValueError):
        return jsonify({'message': 'Invalid input data'}), 400

    # Simple rule-based prediction for demo (replace with ML model)
    if petal_length < 2.5:
        predicted_class = 0  # Setosa
    elif petal_width < 1.8:
        predicted_class = 1  # Versicolor
    else:
        predicted_class = 2  # Virginica
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO predictions (sepal_length, sepal_width, petal_length, petal_width, predicted_class)
            VALUES (?, ?, ?, ?, ?)
        ''', (sepal_length, sepal_width, petal_length, petal_width, predicted_class))
        conn.commit()
    finally:
        conn.close()
    
    return jsonify({
        'sepal_length': sepal_length,
        'sepal_width': sepal_width,
        'petal_length': petal_length,
        'petal_width': petal_width,
        'predicted_class': int(predicted_class)
    }), 200

@app.route('/', methods=['GET'])
def home():
    """
    Home route
    ---
    responses:
      200:
        description: API is working
    """
    return jsonify({'message': 'Flask API is working on Vercel!', 'version': '1.0.0'}), 200

# Vercel requires the app to be accessible via this function
def handler(request):
    return app(request.environ, lambda status, headers: None)

if __name__ == '__main__':
    app.run(debug=True)
