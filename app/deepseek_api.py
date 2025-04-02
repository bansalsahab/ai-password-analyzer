import os
import requests
import json
import random
import string

def generate_ai_suggestion(password: str) -> dict:
    """
    Uses DeepSeek-v3-base via OpenRouter API to analyze password
    Returns: {'suggestion': str, 'weak_patterns': list, 'risk_analysis': str, 'improved_password': str, 'improvement_reasoning': str}
    """
    original_password = password  # Store original password for fallback
    API_KEY = os.getenv('OPENROUTER_KEY')
    
    # If no API key is set, use the fallback mechanism
    if not API_KEY:
        print("Warning: No OpenRouter API key found. Using fallback analysis.")
        return generate_fallback_suggestion(original_password)
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "https://localhost:5000/",
        "Content-Type": "application/json"
    }
    
    system_prompt = """Analyze this password as cybersecurity expert:
    - Detect leetspeak variations and common substitutions
    - Identify keyboard patterns (qwerty, etc.)
    - Find cultural/meme references
    - Check for multilingual vulnerabilities
    - Suggest a significantly stronger alternative password based on the original
    - Explain specific improvements made to the original password
    - Output in JSON format with 'weaknesses', 'suggestions', 'improved_password', and 'improvement_reasoning'"""
    
    try:
        print(f"Analyzing password: {password}")  # Log the password being analyzed
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json={
                "model": "deepseek/deepseek-v3-base:free",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Password: {password}"}
                ],
                "temperature": 0.3,
                "max_tokens": 250
            },
            timeout=10  # Add timeout to prevent hanging
        )
        
        # Check if response was successful
        if response.status_code != 200:
            print(f"API error: {response.status_code} - {response.text}")
            return generate_fallback_suggestion(original_password)
            
        return parse_deepseek_response(response.json(), original_password)
    except Exception as e:
        print(f"Error calling OpenRouter API: {e}")
        return generate_fallback_suggestion(original_password)

def parse_deepseek_response(response_data: dict, original_password: str) -> dict:
    """
    Parse the JSON response from DeepSeek API
    """
    try:
        # Check if the response has the expected structure
        if 'choices' not in response_data or not response_data['choices']:
            print("Invalid API response format: 'choices' not found")
            return generate_fallback_suggestion(original_password)
            
        # Extract the content from the response
        ai_content = response_data.get('choices', [{}])[0].get('message', {}).get('content', '{}')
        
        # Debug the raw content
        print(f"Raw API content: {ai_content[:100]}...")  # Print first 100 chars for debugging
        
        # Try to parse JSON from the content
        try:
            parsed_content = json.loads(ai_content)
        except json.JSONDecodeError:
            # Try to extract JSON if it's embedded in other text
            import re
            json_match = re.search(r'(\{.*\})', ai_content, re.DOTALL)
            if json_match:
                try:
                    parsed_content = json.loads(json_match.group(1))
                except:
                    raise json.JSONDecodeError("Could not extract valid JSON", ai_content, 0)
            else:
                raise
        
        # Format the response
        return {
            'suggestion': parsed_content.get('suggestions', 'No suggestions available'),
            'weak_patterns': parsed_content.get('weaknesses', []),
            'risk_analysis': parsed_content.get('risk_analysis', 'No risk analysis available'),
            'improved_password': parsed_content.get('improved_password', ''),
            'improvement_reasoning': parsed_content.get('improvement_reasoning', '')
        }
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"Error parsing API response: {e}")
        return generate_fallback_suggestion(original_password)

def generate_fallback_suggestion(password: str) -> dict:
    """
    Generate a fallback suggestion when the API is not available
    """
    # Identify basic weaknesses
    weaknesses = []
    
    if not password:
        password = "password123"  # Default if no password is provided
        print("No password provided, using default for analysis")
    
    print(f"Fallback analyzing password: '{password}'")  # Log the actual password being analyzed
    
    if len(password) < 12:
        weaknesses.append("Password is too short")
    
    has_upper = any(c.isupper() for c in password)
    if not has_upper:
        weaknesses.append("No uppercase letters")
    
    has_lower = any(c.islower() for c in password)
    if not has_lower:
        weaknesses.append("No lowercase letters")
    
    has_digit = any(c.isdigit() for c in password)
    if not has_digit:
        weaknesses.append("No numbers")
    
    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in password)
    if not has_special:
        weaknesses.append("No special characters")
    
    # Check for common patterns - only if they're actually in the password
    common_patterns = ["123", "abc", "qwerty", "password", "admin"]
    for pattern in common_patterns:
        if pattern.lower() in password.lower():
            weaknesses.append(f"Contains common pattern '{pattern}'")
    
    # Generate an improved password by adding complexity
    improved = list(password)
    
    # Ensure it has uppercase
    if not has_upper:
        for i in range(len(improved)):
            if improved[i].islower():
                improved[i] = improved[i].upper()
                break
    
    # Ensure it has lowercase
    if not has_lower:
        for i in range(len(improved)):
            if improved[i].isupper():
                improved[i] = improved[i].lower()
                break
    
    # Ensure it has a digit
    if not has_digit:
        improved.append(random.choice(string.digits))
    
    # Ensure it has a special character
    if not has_special:
        improved.append(random.choice("!@#$%^&*"))
    
    # Ensure minimum length
    while len(improved) < 12:
        improved.append(random.choice(string.ascii_letters + string.digits + "!@#$%^&*"))
    
    # Replace common letter-to-number substitutions to add complexity
    substitutions = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    for i, char in enumerate(improved):
        if char.lower() in substitutions and random.random() > 0.7:  # 30% chance to substitute
            improved[i] = substitutions[char.lower()]
    
    improved_password = ''.join(improved)
    
    # Create reasoning
    reasoning = "The improved password:"
    if len(password) < 12:
        reasoning += " has been lengthened to at least 12 characters;"
    if not has_upper:
        reasoning += " adds uppercase letters;"
    if not has_lower:
        reasoning += " adds lowercase letters;"
    if not has_digit:
        reasoning += " includes numbers;"
    if not has_special:
        reasoning += " contains special characters;"
    reasoning += " and incorporates letter-to-symbol substitutions for increased entropy."
    
    # General suggestion
    suggestion = "Use a strong password with at least 12 characters including uppercase letters, lowercase letters, numbers, and special characters. Avoid common patterns and personal information."
    
    return {
        'suggestion': suggestion,
        'weak_patterns': weaknesses,
        'risk_analysis': "Analyzed using local pattern detection. For more detailed analysis, please set up your OpenRouter API key.",
        'improved_password': improved_password,
        'improvement_reasoning': reasoning
    } 