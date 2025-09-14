"""
Shared globals module to avoid circular imports.
Contains the ML model and predictions cache.
"""

# Global variables that will be initialized by main.py
model = None
predictions_cache = {}

def initialize_model(model_instance):
    """Initialize the global model instance."""
    global model
    model = model_instance

def get_model():
    """Get the global model instance."""
    return model

def get_predictions_cache():
    """Get the global predictions cache."""
    return predictions_cache
