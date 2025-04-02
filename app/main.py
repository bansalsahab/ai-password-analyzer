from flask import Flask, render_template, request, jsonify
from app.deepseek_api import generate_ai_suggestion
from app.utils.entropy import calculate_advanced_entropy
from app.utils.crack_time import estimate_crack_time
import os
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv('config.env')

# Initialize ML model
def predict_password_strength(password: str) -> float:
    """
    Predict password strength using trained ML model
    Returns a score between 0.0 and 1.0
    """
    # This is a simplified placeholder for ML prediction
    # In production, we would load a trained model (joblib/h5)
    
    # Simple scoring based on length and character types
    length_score = min(len(password) / 20, 1.0)  # Length up to 20 chars
    
    # Character type diversity
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    char_type_score = (has_lower + has_upper + has_digit + has_symbol) / 4
    
    # Combine scores (60% character diversity, 40% length)
    return 0.4 * length_score + 0.6 * char_type_score

# Initialize Flask app
app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.form['password']
    logger.debug(f"Analyzing password from form: '{password}'")
    
    # Core analysis pipeline
    results = {
        'entropy': calculate_advanced_entropy(password),
        'crack_time': estimate_crack_time(password),
        'ml_score': predict_password_strength(password),
        'ai_analysis': generate_ai_suggestion(password)
    }
    
    logger.debug(f"Analysis results for strength score: {results['ml_score']}")
    logger.debug(f"Analysis weak patterns: {results['ai_analysis']['weak_patterns']}")
    
    return jsonify(results)

if __name__ == '__main__':
    # Check if API key is set
    if not os.getenv('OPENROUTER_KEY'):
        logger.warning("OPENROUTER_KEY not set in config.env")
    else:
        logger.info(f"Using API key: {os.getenv('OPENROUTER_KEY')[:8]}...")
    
    # Run the Flask app
    app.run(debug=True) 