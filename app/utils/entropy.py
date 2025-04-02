"""
Advanced entropy calculations for password strength analysis
"""
import math
from collections import Counter

def calculate_shannon_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of a password
    H = -sum(p_i * log_2(p_i)) where p_i is the probability of character i
    """
    if not password:
        return 0.0
    
    # Count occurrences of each character
    char_counts = Counter(password)
    
    # Calculate entropy
    length = len(password)
    entropy = 0.0
    
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_character_set_size(password: str) -> int:
    """
    Determine the size of the character set used in the password
    """
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    
    charset_size = 0
    if has_lowercase:
        charset_size += 26  # a-z
    if has_uppercase:
        charset_size += 26  # A-Z
    if has_digits:
        charset_size += 10  # 0-9
    if has_symbols:
        charset_size += 33  # Common symbols
    
    return charset_size

def calculate_ideal_entropy(password: str) -> float:
    """
    Calculate ideal entropy based on character set size
    E = L * log_2(R) where L is length and R is charset size
    """
    length = len(password)
    charset_size = calculate_character_set_size(password)
    
    if charset_size == 0:
        return 0.0
    
    return length * math.log2(charset_size)

def detect_patterns(password: str) -> dict:
    """
    Detect common patterns in passwords
    """
    patterns = {
        'keyboard_sequences': 0,
        'repeats': 0,
        'sequential_digits': 0,
        'sequential_chars': 0
    }
    
    # Example keyboard sequences
    keyboard_rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890"
    ]
    
    # Check for keyboard patterns
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i+3] in password.lower():
                patterns['keyboard_sequences'] += 1
    
    # Check for repeating characters (aaa, 111, etc.)
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            patterns['repeats'] += 1
    
    # Check for sequential digits (123, 456, etc.)
    for i in range(len(password) - 2):
        if (password[i].isdigit() and password[i+1].isdigit() and password[i+2].isdigit() and
            int(password[i+1]) == int(password[i]) + 1 and
            int(password[i+2]) == int(password[i+1]) + 1):
            patterns['sequential_digits'] += 1
    
    # Check for sequential characters (abc, def, etc.)
    for i in range(len(password) - 2):
        if (password[i].isalpha() and password[i+1].isalpha() and password[i+2].isalpha() and
            ord(password[i+1].lower()) == ord(password[i].lower()) + 1 and
            ord(password[i+2].lower()) == ord(password[i+1].lower()) + 1):
            patterns['sequential_chars'] += 1
    
    return patterns

def calculate_advanced_entropy(password: str) -> dict:
    """
    Calculate advanced entropy metrics for a password
    """
    shannon_entropy = calculate_shannon_entropy(password)
    ideal_entropy = calculate_ideal_entropy(password)
    patterns = detect_patterns(password)
    
    # Adjust entropy based on detected patterns
    pattern_penalty = sum(patterns.values()) * 0.5
    adjusted_entropy = max(0, shannon_entropy - pattern_penalty)
    
    # Calculate entropy ratio (actual/ideal)
    entropy_ratio = 0
    if ideal_entropy > 0:
        entropy_ratio = adjusted_entropy / ideal_entropy
    
    return {
        'length': len(password),
        'shannon_entropy': shannon_entropy,
        'ideal_entropy': ideal_entropy,
        'adjusted_entropy': adjusted_entropy,
        'entropy_ratio': entropy_ratio,
        'character_set_size': calculate_character_set_size(password),
        'patterns': patterns
    } 