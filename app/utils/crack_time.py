"""
Hashcat simulation logic for password cracking time estimation
"""
import math
from app.utils.entropy import calculate_character_set_size

# Constants for hashcat-style password cracking
HASH_RATES = {
    'md5': 32_000_000_000,  # 32 billion hashes/sec
    'sha1': 13_000_000_000,  # 13 billion hashes/sec
    'bcrypt': 24_000,        # 24 thousand hashes/sec
    'argon2': 1_500          # 1.5 thousand hashes/sec
}

# Attack methods
ATTACK_METHODS = {
    'dictionary': 0.001,  # Factor representing efficiency (lower means faster cracking)
    'mask': 0.01,         # More efficient than brute force, less than dictionary
    'brute_force': 1.0,   # Base efficiency
    'hybrid': 0.05        # Combination of dictionary and mask
}

def estimate_dict_attack_time(password: str) -> float:
    """
    Estimate time to crack using dictionary attack
    Based on the commonality of the password
    """
    # Some common password detection
    common_passwords = ["password", "123456", "admin", "welcome", "qwerty"]
    common_patterns = ["password1", "admin123", "letmein", "welcome1"]
    
    # Check for direct matches or simple variations
    if password.lower() in common_passwords:
        return 0.001  # Almost instant
    
    # Check for common pattern variations
    for pattern in common_patterns:
        if pattern in password.lower():
            return 0.1  # Very quick
    
    # Estimate based on length (very simple heuristic)
    if len(password) <= 8:
        return 60  # 1 minute for short common-pattern passwords
    elif len(password) <= 12:
        return 3600  # 1 hour for medium-length passwords
    else:
        return 86400  # 1 day for longer passwords
    
def estimate_brute_force_time(password: str) -> float:
    """
    Estimate time to crack using brute force attack
    """
    charset_size = calculate_character_set_size(password)
    
    # If no recognizable characters, default to printable ASCII (95 chars)
    if charset_size == 0:
        charset_size = 95
    
    # Time = charset_size^length / hash_rate
    # Using bcrypt as a reference point for a secure hash
    possible_combinations = charset_size ** len(password)
    seconds_to_crack = possible_combinations / HASH_RATES['bcrypt']
    
    return seconds_to_crack

def estimate_mask_attack_time(password: str) -> float:
    """
    Estimate time to crack using mask attack (pattern-based)
    """
    # Define patterns that would make mask attacks faster
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    
    # Count the types of characters used
    char_type_count = sum([has_lowercase, has_uppercase, has_digits, has_symbols])
    
    # If only one character type is used, mask attacks are very effective
    if char_type_count == 1:
        efficiency_factor = 0.001
    # If all character types are used, mask attacks are less effective
    elif char_type_count >= 3:
        efficiency_factor = 0.1
    else:
        efficiency_factor = 0.01
    
    # Calculate the brute force time and apply the efficiency factor
    brute_force_time = estimate_brute_force_time(password)
    return brute_force_time * efficiency_factor

def determine_most_likely_attack(password: str) -> str:
    """
    Determine the most likely successful attack method
    """
    dict_time = estimate_dict_attack_time(password)
    brute_time = estimate_brute_force_time(password)
    mask_time = estimate_mask_attack_time(password)
    
    times = {
        'dictionary': dict_time,
        'brute_force': brute_time,
        'mask': mask_time
    }
    
    return min(times, key=times.get)

def estimate_crack_time(password: str) -> dict:
    """
    Estimate the time it would take to crack a password using various methods
    """
    # Calculate estimated crack times for different methods
    dict_time = estimate_dict_attack_time(password)
    brute_time = estimate_brute_force_time(password)
    mask_time = estimate_mask_attack_time(password)
    
    # Determine the most likely successful attack
    most_likely_attack = determine_most_likely_attack(password)
    fastest_time = min(dict_time, brute_time, mask_time)
    
    # Format the times in human-readable format
    def format_time(seconds):
        if seconds < 1:
            return "instantly"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 2592000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000:
            return f"{seconds/2592000:.1f} months"
        elif seconds < 315360000:
            return f"{seconds/31536000:.1f} years"
        else:
            centuries = seconds / 31536000 / 100
            if centuries > 1e15:
                return "heat death of the universe"
            elif centuries > 1e10:
                return "billions of billions of years"
            else:
                return f"{centuries:.1f} centuries"
    
    return {
        'fastest_method': most_likely_attack,
        'dictionary_attack': format_time(dict_time),
        'brute_force': format_time(brute_time),
        'mask_attack': format_time(mask_time),
        'estimated_time': format_time(fastest_time),
        'time_seconds': fastest_time
    } 