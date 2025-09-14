from flask import Blueprint, request, jsonify
from extensions import db
from models import User, Prediction
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, create_access_token
import globals as app_globals

import numpy as np

bp = Blueprint('main', __name__)

@bp.route('/register', methods=['POST'])
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
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@bp.route('/login', methods=['POST'])
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
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid email or password'}), 401
    token = create_access_token(identity=str(user.id))
    return jsonify({'message': 'User logged in successfully', 'token': token}), 200

@bp.route('/protected', methods=['GET'])
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

@bp.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    """
    Make a prediction using the Iris model
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

    features = (sepal_length, sepal_width, petal_length, petal_width)
    
    # Get model and cache from globals
    model = app_globals.get_model()
    predictions_cache = app_globals.get_predictions_cache()
    
    # Check if prediction is cached
    if features in predictions_cache:
        predicted_class = predictions_cache[features]
    else:
        input_data = np.array([features])
        predicted_class = model.predict([features])[0]
        predictions_cache[features] = predicted_class

    # Converta predicted_class para int antes de salvar
    predicted_class = int(predicted_class)

    new_prediction = Prediction(
        sepal_length=sepal_length,
        sepal_width=sepal_width,
        petal_length=petal_length,
        petal_width=petal_width,
        predicted_class=predicted_class
    )
    db.session.add(new_prediction)
    db.session.commit()
    return jsonify({
        'sepal_length': sepal_length,
        'sepal_width': sepal_width,
        'petal_length': petal_length,
        'petal_width': petal_width,
        'predicted_class': predicted_class
    }), 200

@bp.route('/predictions', methods=['GET'])
@jwt_required()
def get_predictions():
    """
    Get all predictions made so far
    ---
    tags:
      - Prediction
    responses:
      200:
        description: List of all predictions
    """
    predictions = Prediction.query.all()
    result = []
    for pred in predictions:
        result.append({
            'id': int(pred.id),
            'sepal_length': float(pred.sepal_length),
            'sepal_width': float(pred.sepal_width),
            'petal_length': float(pred.petal_length),
            'petal_width': float(pred.petal_width),
            'predicted_class': int(pred.predicted_class),
            'created_at': pred.created_at.isoformat() if pred.created_at else None
        })
    return jsonify(result), 200