from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_from_directory,
    redirect,
    url_for,
    flash,
    session,
)
import os
import re
import math
import hashlib
import random
import string
import time
from collections import Counter
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_migrate import Migrate
from datetime import datetime, timedelta
import json

# Import models and forms
from app.models import db, User, Password
from app.forms import RegistrationForm, LoginForm, SavePasswordForm

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URI", "sqlite:///password_analyzer.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Configure longer session lifetime (1 day)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)
# Ensure session cookies work across all browsers
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production with HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Path to RockYou dataset
ROCKYOU_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rockyou.txt")

# Global variable to store common passwords (loaded lazily)
common_passwords = set()
common_patterns = {}


def load_rockyou_dataset():
    """Load RockYou dataset into memory for fast checking"""
    global common_passwords
    global common_patterns

    print("Loading RockYou dataset...")
    try:
        with open(ROCKYOU_PATH, "r", errors="ignore") as f:
            # Load the full dataset instead of just 100,000 passwords
            passwords = [line.strip() for line in f.readlines()]
            common_passwords = set(passwords)

            # Extract common patterns
            patterns = {
                "numbers_suffix": 0,
                "special_suffix": 0,
                "capital_first": 0,
                "leetspeak": 0,
                "keyboard_walks": 0,
                "year_patterns": 0,
            }

            # For pattern analysis, use a sample to keep it efficient
            pattern_sample = random.sample(passwords, min(500000, len(passwords)))

            # Count pattern occurrences
            for password in pattern_sample:
                # Check for numbers at the end
                if re.search(r"\d+$", password):
                    patterns["numbers_suffix"] += 1

                # Check for special chars at the end
                if re.search(r"[!@#$%^&*]+$", password):
                    patterns["special_suffix"] += 1

                # Check for capital first letter
                if re.match(r"^[A-Z]", password):
                    patterns["capital_first"] += 1

                # Check for leetspeak (simplified)
                if re.search(r"[4@3€31!70]", password):
                    patterns["leetspeak"] += 1

                # Check for keyboard walks
                if re.search(r"(qwer|asdf|zxcv|1234|wasd)", password, re.IGNORECASE):
                    patterns["keyboard_walks"] += 1

                # Check for years
                if re.search(r"(19\d\d|20\d\d)", password):
                    patterns["year_patterns"] += 1

            # Calculate percentages
            sample_size = len(pattern_sample)
            common_patterns = {k: (v / sample_size) * 100 for k, v in patterns.items()}
        print(f"Loaded {len(common_passwords)} passwords from RockYou dataset")
        print(
            f"Pattern analysis on sample of {min(500000, len(passwords))} passwords: {common_patterns}"
        )
    except FileNotFoundError:
        print(f"Warning: RockYou dataset file not found at {ROCKYOU_PATH}")
        print("Using fallback data for common password patterns")
        common_passwords = set(
            [
                "password",
                "123456",
                "12345678",
                "qwerty",
                "abc123",
                "monkey",
                "1234567",
                "letmein",
                "trustno1",
                "dragon",
                "baseball",
                "111111",
                "iloveyou",
                "master",
                "sunshine",
                "ashley",
                "bailey",
                "passw0rd",
                "shadow",
                "123123",
                "654321",
                "superman",
                "qazwsx",
                "michael",
                "football",
            ]
        )
        # Default pattern frequencies based on known password statistics
        common_patterns = {
            "numbers_suffix": 30.0,
            "special_suffix": 8.0,
            "capital_first": 15.0,
            "leetspeak": 7.0,
            "keyboard_walks": 20.0,
            "year_patterns": 12.0,
        }
        print("Using fallback common passwords and pattern data")
    except Exception as e:
        print(f"Error loading RockYou dataset: {e}")
        # Create an empty set as fallback
        common_passwords = set()
        common_patterns = {
            "numbers_suffix": 30.0,
            "special_suffix": 8.0,
            "capital_first": 15.0,
            "leetspeak": 7.0,
            "keyboard_walks": 20.0,
            "year_patterns": 12.0,
        }


# Initialize dataset before request handling
load_rockyou_dataset()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory("static", path)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.verify_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Store master password temporarily for this session (will be used for decryption)
            # This is a security tradeoff - we keep it in the session for usability
            # Store it as a variable that won't be lost during redirection
            session["master_password"] = form.password.data
            # Set permanent session to avoid quick expiration
            session.permanent = True

            # Set a flash message to confirm the login succeeded and master password is stored
            flash("Login successful! Your passwords are now accessible.", "success")

            # Force a session save to ensure all data is written before redirect
            session.modified = True

            next_page = request.args.get("next")
            # Add debug logging
            print(
                f"Login successful for user {user.username}. Redirecting to: {next_page or 'dashboard'}"
            )

            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    # Remove master password from session
    if "master_password" in session:
        session.pop("master_password")

    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Check if user is authenticated (redundant with @login_required but added for clarity)
    if not current_user.is_authenticated:
        flash("Please log in to access your dashboard.", "warning")
        return redirect(url_for("login"))

    # Log dashboard access for debugging
    print(
        f"Dashboard accessed by user: {current_user.username}, Session active: {session.get('master_password') is not None}"
    )

    # Check if master password is in session
    has_master_password = "master_password" in session

    # If master password is missing but user is logged in, show a warning
    if not has_master_password:
        flash(
            "Your session needs to be refreshed to view encrypted passwords.", "warning"
        )

    # Get user's saved passwords
    saved_passwords = Password.query.filter_by(user_id=current_user.id).all()

    # Convert to dict without decrypted passwords
    passwords_data = [p.to_dict() for p in saved_passwords]

    return render_template(
        "dashboard.html",
        passwords=passwords_data,
        has_master_password=has_master_password,
    )


@app.route("/analyze", methods=["POST"])
def analyze_password():
    data = request.json
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    # Calculate basic entropy
    entropy = calculate_entropy(password)

    # Calculate crack time
    crack_time = estimate_crack_time(password, entropy)

    # Check against common passwords
    in_rockyou = password in common_passwords

    # Identify patterns
    patterns = identify_patterns(password)

    # Generate AI analysis
    ai_analysis = generate_ai_analysis(password, patterns, in_rockyou, entropy)

    # Identify vulnerabilities
    vulnerabilities = identify_vulnerabilities(password, patterns, in_rockyou)

    # Generate improved password suggestion
    improved_password, improvement_reason = suggest_improved_password(
        password, vulnerabilities
    )

    # Calculate pattern data for visualization
    pattern_data = calculate_pattern_data(password)

    # Prepare response
    score = min(100, max(0, calculate_score(password, entropy, patterns, in_rockyou)))

    response = {
        "score": score,
        "entropy": entropy,
        "crack_time": crack_time,
        "in_common_db": in_rockyou,
        "patterns": patterns,
        "ai_analysis": ai_analysis,
        "vulnerabilities": vulnerabilities,
        "improved_password": improved_password,
        "improvement_reason": improvement_reason,
        "pattern_data": pattern_data,
    }

    # If user is logged in, provide option to save password
    if current_user.is_authenticated:
        response["can_save"] = True

    return jsonify(response)


@app.route("/save-password", methods=["POST"])
@login_required
def save_password():
    # Get form data
    data = request.json
    plain_password = data.get("password")
    website = data.get("website", "")
    label = data.get("label", "")
    score = int(data.get("score", 0))
    entropy = float(data.get("entropy", 0))

    if not plain_password:
        return jsonify({"error": "Password is required"}), 400

    # Make sure we have the master password in session
    if "master_password" not in session:
        return jsonify({"error": "Session expired. Please log in again."}), 401

    try:
        # Encrypt the password
        encrypted_password = current_user.encrypt_password(plain_password)

        if not encrypted_password:
            return (
                jsonify(
                    {
                        "error": "Failed to encrypt password. Please refresh your session."
                    }
                ),
                500,
            )

        # Create and save password record
        password = Password(
            user_id=current_user.id,
            encrypted_password=encrypted_password,
            website=website,
            label=label or "Unnamed Password",  # Ensure label has a default value
            score=score,
            entropy=entropy,
        )

        db.session.add(password)
        db.session.commit()

        # Print confirmation to server logs
        print(
            f"Password saved successfully. ID: {password.id}, User: {current_user.username}, Label: {password.label}"
        )

        return jsonify(
            {
                "success": True,
                "message": "Password saved successfully",
                "password_id": password.id,
            }
        )
    except Exception as e:
        # Log the error
        print(f"Error saving password: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Failed to save password: {str(e)}"}), 500


@app.route("/passwords")
@login_required
def list_passwords():
    # Get user's saved passwords
    saved_passwords = Password.query.filter_by(user_id=current_user.id).all()

    # Convert to dict without decrypted passwords
    passwords_data = [p.to_dict() for p in saved_passwords]

    return jsonify(passwords_data)


@app.route("/passwords/<int:password_id>")
@login_required
def view_password(password_id):
    # Get password by ID
    password = Password.query.filter_by(
        id=password_id, user_id=current_user.id
    ).first_or_404()

    # Check if master password exists in session
    master_password = session.get("master_password", "")
    if not master_password:
        print(
            f"No master password in session for user {current_user.username} when viewing password {password_id}"
        )
        return jsonify(
            {
                "id": password.id,
                "website": password.website,
                "label": password.label,
                "score": password.score,
                "entropy": password.entropy,
                "created_at": password.created_at.isoformat(),
                "last_updated": password.last_updated.isoformat(),
                "decryption_failed": True,
                "error": "Session expired. Please refresh your session.",
            }
        )

    # Try to decrypt the password
    try:
        # Attempt direct decryption
        decrypted = current_user.decrypt_password(
            password.encrypted_password, master_password
        )

        # Create the response
        password_data = {
            "id": password.id,
            "website": password.website,
            "label": password.label,
            "score": password.score,
            "entropy": password.entropy,
            "created_at": password.created_at.isoformat(),
            "last_updated": password.last_updated.isoformat(),
        }

        if decrypted:
            # Successfully decrypted
            password_data["password"] = decrypted
            print(
                f"Successfully decrypted password {password_id} for user {current_user.username}"
            )
        else:
            # Failed to decrypt
            password_data["decryption_failed"] = True
            print(
                f"Failed to decrypt password {password_id} for user {current_user.username}"
            )

        return jsonify(password_data)

    except Exception as e:
        print(f"Error decrypting password {password_id}: {str(e)}")
        return jsonify(
            {
                "id": password.id,
                "website": password.website,
                "label": password.label,
                "score": password.score,
                "entropy": password.entropy,
                "created_at": password.created_at.isoformat(),
                "last_updated": password.last_updated.isoformat(),
                "decryption_failed": True,
                "error": str(e),
            }
        )


@app.route("/passwords/<int:password_id>", methods=["DELETE"])
@login_required
def delete_password(password_id):
    # Get password by ID
    password = Password.query.filter_by(
        id=password_id, user_id=current_user.id
    ).first_or_404()

    # Delete password
    db.session.delete(password)
    db.session.commit()

    return jsonify({"success": True, "message": "Password deleted successfully"})


@app.route("/init-db")
def init_db():
    try:
        db.create_all()
        return jsonify({"message": "Database initialized successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/refresh-session", methods=["GET", "POST"])
@login_required
def refresh_session():
    """
    Allow a logged-in user to re-enter their master password to refresh the session
    without having to fully log out and log back in.
    """
    if request.method == "POST":
        master_password = request.form.get("master_password")

        if not master_password:
            flash("Master password is required.", "danger")
            return render_template("refresh_session.html")

        # Verify the password
        if current_user.verify_password(master_password):
            # Update the session with the new master password
            session["master_password"] = master_password
            session.permanent = True

            # Log the success (without the actual password)
            print(f"Session refreshed successfully for user: {current_user.username}")

            flash(
                "Your session has been refreshed. You can now view your passwords.",
                "success",
            )
            return redirect(url_for("dashboard"))
        else:
            # Log the failure
            print(f"Failed session refresh attempt for user: {current_user.username}")
            flash("Invalid master password. Please try again.", "danger")

    return render_template("refresh_session.html")


def calculate_entropy(password):
    """Calculate Shannon entropy of password"""
    if not password:
        return 0

    # Count character frequencies
    char_count = Counter(password)

    # Calculate entropy
    length = len(password)
    entropy = 0

    for count in char_count.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    # Multiply by length for total entropy
    entropy *= length

    # Adjust for character set complexity
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 33

    theoretical_max = math.log2(charset_size) * length

    # Weight the entropy calculation
    return 0.75 * entropy + 0.25 * theoretical_max


def identify_patterns(password):
    """Identify common patterns in the password"""
    patterns = {}

    # Check for dictionary words (simplified)
    if len(password) >= 4:
        patterns["dictionary_word"] = True

    # Check for sequential characters
    if re.search(
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890)",
        password,
        re.IGNORECASE,
    ):
        patterns["sequential_chars"] = True

    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        patterns["repeated_chars"] = True

    # Check for keyboard patterns
    if re.search(
        r"(qwert|asdfg|zxcvb|12345|09876|qazws|wsxed|edcrf|rfvtg)",
        password,
        re.IGNORECASE,
    ):
        patterns["keyboard_pattern"] = True

    # Check for numbers only
    if re.match(r"^\d+$", password):
        patterns["numbers_only"] = True

    # Check for letters only
    if re.match(r"^[a-zA-Z]+$", password):
        patterns["letters_only"] = True

    # Check for common suffixes
    if re.search(r"\d{1,4}$", password):
        patterns["number_suffix"] = True

    if re.search(r"[!@#$%^&*]+$", password):
        patterns["special_suffix"] = True

    # Check for common formats
    if re.match(r"^[A-Z][a-z]+\d+$", password):
        patterns["capital_word_number"] = True

    # Check for date formats
    if re.search(r"(19\d\d|20\d\d)", password):
        patterns["year"] = True

    if re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", password):
        patterns["date_format"] = True

    # Check for leetspeak
    if re.search(r"[4@3€31!70]", password):
        patterns["leetspeak"] = True

    return patterns


def calculate_score(password, entropy, patterns, in_rockyou):
    """Calculate overall password score"""
    score = 0

    # Base score from entropy (max 70 points)
    score += min(70, entropy)

    # Length bonus (max 10 points)
    length = len(password)
    if length >= 12:
        score += 10
    elif length >= 8:
        score += 5

    # Character set diversity (max 10 points)
    char_set_score = 0
    if re.search(r"[a-z]", password):
        char_set_score += 2.5
    if re.search(r"[A-Z]", password):
        char_set_score += 2.5
    if re.search(r"[0-9]", password):
        char_set_score += 2.5
    if re.search(r"[^a-zA-Z0-9]", password):
        char_set_score += 2.5
    score += char_set_score

    # Penalize for patterns (max -30 points)
    pattern_penalty = 0
    if patterns.get("dictionary_word"):
        pattern_penalty += 5
    if patterns.get("sequential_chars"):
        pattern_penalty += 5
    if patterns.get("repeated_chars"):
        pattern_penalty += 5
    if patterns.get("keyboard_pattern"):
        pattern_penalty += 10
    if patterns.get("numbers_only"):
        pattern_penalty += 15
    if patterns.get("letters_only"):
        pattern_penalty += 10
    if patterns.get("number_suffix"):
        pattern_penalty += 3
    if patterns.get("special_suffix"):
        pattern_penalty += 2
    if patterns.get("capital_word_number"):
        pattern_penalty += 5
    if patterns.get("year"):
        pattern_penalty += 5
    if patterns.get("date_format"):
        pattern_penalty += 8

    # Cap the penalty
    pattern_penalty = min(30, pattern_penalty)
    score -= pattern_penalty

    # Severe penalty if password is in RockYou dataset (-40 points)
    if in_rockyou:
        score -= 40

    return max(0, score)


def estimate_crack_time(password, entropy):
    """Estimate time to crack the password using different attack vectors"""

    # Define cracking speeds (guesses per second)
    speeds = {
        "online_throttled": 100,  # 100 guesses per second
        "online_unthrottled": 10000,  # 10k guesses per second
        "offline_slow_hash": 1000000,  # 1M guesses per second (bcrypt/PBKDF2)
        "offline_fast_hash": 1000000000,  # 1B guesses per second (MD5/SHA)
        "offline_gpu_farm": 100000000000,  # 100B guesses per second (large GPU farm)
        "quantum_computer": 10000000000000,  # 10T guesses per second (future quantum)
    }

    # Calculate possible combinations
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 33

    charset_size = max(charset_size, 26)  # Assume at least lowercase letters

    # If password is in common database, it can be cracked instantly
    if password in common_passwords:
        guesses = (
            1000  # Assume it's within the first 1000 attempts of a dictionary attack
        )
    else:
        # Use entropy to calculate guesses needed, with adjustment for known patterns
        guesses = 2**entropy

    # Calculate times for each attack vector
    attack_times = {}
    for attack, speed in speeds.items():
        seconds = guesses / speed
        attack_times[attack] = format_time(seconds)

    # Get human-readable overall time (based on offline_fast_hash as reference)
    human_time = attack_times["offline_fast_hash"]

    return {"human": human_time, "attack_times": attack_times}


def format_time(seconds):
    """Format time in seconds to a human-readable string"""
    if seconds < 0.001:
        return "Instantly"
    if seconds < 1:
        return f"{seconds*1000:.0f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 2592000:
        return f"{seconds/86400:.1f} days"
    if seconds < 31536000:
        return f"{seconds/2592000:.1f} months"
    if seconds < 3153600000:
        return f"{seconds/31536000:.1f} years"
    if seconds < 315360000000:
        return f"{seconds/31536000:.0f} years"

    return f"{seconds/31536000/100:.0f} centuries"


def identify_vulnerabilities(password, patterns, in_rockyou):
    """Identify specific vulnerabilities in the password"""
    vulnerabilities = {}

    if in_rockyou:
        vulnerabilities["Common Password"] = {
            "description": "This password appears in the RockYou data breach of over 32 million passwords. Hackers will try these passwords first.",
            "severity": "Critical",
        }

    if len(password) < 8:
        vulnerabilities["Too Short"] = {
            "description": "Passwords should be at least 8 characters long to resist brute force attacks.",
            "severity": "High",
        }

    if patterns.get("dictionary_word"):
        vulnerabilities["Dictionary Word"] = {
            "description": "Your password may be a common word or name which is vulnerable to dictionary attacks.",
            "severity": "Medium",
        }

    if patterns.get("sequential_chars"):
        vulnerabilities["Sequential Characters"] = {
            "description": "Your password contains sequential characters (like 'abc' or '123') which are easy to guess.",
            "severity": "Medium",
        }

    if patterns.get("repeated_chars"):
        vulnerabilities["Repeated Characters"] = {
            "description": "Your password contains repeated characters which reduce entropy and make it easier to crack.",
            "severity": "Low",
        }

    if patterns.get("keyboard_pattern"):
        vulnerabilities["Keyboard Pattern"] = {
            "description": "Your password follows a keyboard pattern (like 'qwerty') which is one of the first patterns hackers try.",
            "severity": "High",
        }

    if patterns.get("numbers_only"):
        vulnerabilities["Numbers Only"] = {
            "description": "Your password contains only numbers, severely limiting its complexity.",
            "severity": "Critical",
        }

    if patterns.get("letters_only"):
        vulnerabilities["Letters Only"] = {
            "description": "Your password contains only letters. Adding numbers and special characters would make it stronger.",
            "severity": "High",
        }

    if patterns.get("number_suffix"):
        vulnerabilities["Number Suffix"] = {
            "description": "Adding numbers at the end of a password is a common pattern that attackers check first.",
            "severity": "Medium",
        }

    if patterns.get("year"):
        vulnerabilities["Year Pattern"] = {
            "description": "Your password contains a year, which is a predictable pattern used in over 20% of passwords.",
            "severity": "Medium",
        }

    if patterns.get("date_format"):
        vulnerabilities["Date Format"] = {
            "description": "Your password contains a date format, which significantly reduces the possible combinations.",
            "severity": "Medium",
        }

    if not re.search(r"[A-Z]", password):
        vulnerabilities["No Uppercase"] = {
            "description": "Your password lacks uppercase letters, which reduces its complexity.",
            "severity": "Low",
        }

    if not re.search(r"[0-9]", password):
        vulnerabilities["No Numbers"] = {
            "description": "Your password lacks numbers, which reduces its complexity.",
            "severity": "Low",
        }

    if not re.search(r"[^a-zA-Z0-9]", password):
        vulnerabilities["No Special Characters"] = {
            "description": "Your password lacks special characters, which reduces its complexity.",
            "severity": "Low",
        }

    # Return sorted by severity
    return vulnerabilities


def suggest_improved_password(password, vulnerabilities):
    """Suggest an improved version of the password based on identified vulnerabilities"""
    improved = password
    changes_made = []

    # If it's a common password, generate a completely new one
    if "Common Password" in vulnerabilities:
        return (
            generate_strong_password(),
            "This is a completely new password that follows best practices for security. It's not found in common password databases and has high entropy.",
        )

    # Add length if too short
    if "Too Short" in vulnerabilities:
        additional_chars = "".join(
            random.choices(
                string.ascii_letters + string.digits + string.punctuation,
                k=10 - len(password),
            )
        )
        improved += additional_chars
        changes_made.append(
            f"Added {len(additional_chars)} characters to increase length"
        )

    # Replace sequential characters
    if "Sequential Characters" in vulnerabilities:
        for seq in ["abc", "bcd", "cde", "def", "123", "234", "345", "456"]:
            if seq.lower() in improved.lower():
                replacement = "".join(
                    random.choices(string.ascii_letters + string.digits, k=3)
                )
                improved = improved.replace(seq, replacement)
                changes_made.append(
                    f"Replaced sequential pattern '{seq}' with '{replacement}'"
                )

    # Break keyboard patterns
    if "Keyboard Pattern" in vulnerabilities:
        for pattern in ["qwert", "asdfg", "zxcvb", "12345"]:
            if pattern.lower() in improved.lower():
                replacement = "".join(
                    random.choices(string.ascii_letters + string.digits, k=len(pattern))
                )
                improved = improved.replace(pattern, replacement)
                changes_made.append(
                    f"Replaced keyboard pattern with unpredictable characters"
                )

    # Add uppercase if missing
    if "No Uppercase" in vulnerabilities:
        positions = [i for i, char in enumerate(improved) if char.islower()]
        if positions:
            pos = random.choice(positions)
            improved = improved[:pos] + improved[pos].upper() + improved[pos + 1 :]
            changes_made.append("Added uppercase letter")

    # Add numbers if missing
    if "No Numbers" in vulnerabilities:
        if not any(c.isdigit() for c in improved):
            pos = random.randint(0, len(improved))
            digit = random.choice(string.digits)
            improved = improved[:pos] + digit + improved[pos:]
            changes_made.append(f"Added number '{digit}'")

    # Add special char if missing
    if "No Special Characters" in vulnerabilities:
        if not any(c in string.punctuation for c in improved):
            pos = random.randint(0, len(improved))
            special = random.choice("!@#$%^&*()-_=+")
            improved = improved[:pos] + special + improved[pos:]
            changes_made.append(f"Added special character '{special}'")

    # Break up number suffix with special chars
    if "Number Suffix" in vulnerabilities:
        match = re.search(r"\d+$", improved)
        if match:
            suffix = match.group()
            new_suffix = ""
            for digit in suffix:
                new_suffix += digit + random.choice(
                    string.ascii_letters + string.punctuation
                )
            improved = improved[: -len(suffix)] + new_suffix
            changes_made.append("Broke up number suffix with random characters")

    # Replace years with more complex variations
    if "Year Pattern" in vulnerabilities:
        for year in [
            "2022",
            "2023",
            "2024",
            "1990",
            "1991",
            "1992",
            "1993",
            "1994",
            "1995",
        ]:
            if year in improved:
                replacement = "".join(
                    random.choices(
                        string.ascii_letters + string.digits + string.punctuation, k=4
                    )
                )
                improved = improved.replace(year, replacement)
                changes_made.append(
                    f"Replaced year {year} with unpredictable characters"
                )

    # If no changes were made, make the password more complex
    if not changes_made or improved == password:
        original_len = len(password)
        # Keep first 3 chars as mnemonic device
        prefix = password[: min(3, original_len)]
        # Generate a strong suffix
        suffix = "".join(
            random.choices(
                string.ascii_letters + string.digits + "!@#$%^&*()-_=+",
                k=max(8, original_len),
            )
        )
        improved = prefix + suffix
        changes_made = [
            "Created a more complex variation while preserving the beginning for memorability"
        ]

    # Create explanation
    reason = (
        "This improved password addresses the vulnerabilities by: "
        + ", ".join(changes_made)
        + "."
    )

    return improved, reason


def generate_strong_password():
    """Generate a completely new strong password"""
    # Use different character sets
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*-_=+"

    # Ensure at least one of each type
    pwd = [
        random.choice(upper),
        random.choice(lower),
        random.choice(digits),
        random.choice(special),
    ]

    # Add more random characters
    pwd.extend(random.choices(upper + lower + digits + special, k=8))

    # Shuffle the characters
    random.shuffle(pwd)

    return "".join(pwd)


def generate_ai_analysis(password, patterns, in_rockyou, entropy):
    """Generate AI-like analysis explaining the password's strengths and weaknesses"""

    # Start with a base assessment
    if entropy < 30:
        risk_level = "extremely high"
        base_assessment = f"Your password has very low entropy ({entropy:.1f} bits) and would be cracked almost instantly in most scenarios."
    elif entropy < 60:
        risk_level = "high"
        base_assessment = f"Your password has inadequate entropy ({entropy:.1f} bits) and would be vulnerable to targeted attacks."
    elif entropy < 80:
        risk_level = "moderate"
        base_assessment = f"Your password has moderate entropy ({entropy:.1f} bits) and provides some security against casual attacks."
    else:
        risk_level = "relatively low"
        base_assessment = f"Your password has good entropy ({entropy:.1f} bits) and would resist most attack scenarios."

    # Check if it's in the common database
    if in_rockyou:
        rockyou_text = "<strong>Critical Vulnerability:</strong> This exact password appears in the RockYou data breach, making it trivial to crack using dictionary attacks."
    else:
        rockyou_text = "This password does not appear verbatim in the RockYou data breach database we analyzed."

    # Analyze patterns
    pattern_analysis = []

    if patterns.get("dictionary_word"):
        pattern_analysis.append(
            "Contains recognizable words that make it vulnerable to dictionary attacks"
        )

    if patterns.get("sequential_chars"):
        pattern_analysis.append(
            "Contains sequential characters (like 'abc' or '123') that reduce complexity"
        )

    if patterns.get("repeated_chars"):
        pattern_analysis.append("Contains repeated characters that reduce entropy")

    if patterns.get("keyboard_pattern"):
        pattern_analysis.append(
            "Contains keyboard patterns that are among the first patterns attackers try"
        )

    if patterns.get("numbers_only"):
        pattern_analysis.append(
            "Consists of only numbers, which drastically limits the possible combinations"
        )

    if patterns.get("letters_only"):
        pattern_analysis.append(
            "Contains only letters, missing the extra security from numbers and special characters"
        )

    if patterns.get("number_suffix"):
        pattern_analysis.append(
            "Ends with numbers, a pattern used in over 30% of passwords"
        )

    if patterns.get("year"):
        pattern_analysis.append("Contains a year, which is highly predictable")

    if patterns.get("date_format"):
        pattern_analysis.append(
            "Contains a date pattern, which reduces possible combinations significantly"
        )

    if patterns.get("leetspeak"):
        pattern_analysis.append(
            "Uses leetspeak (replacing letters with numbers/symbols), which is a known pattern that attackers check"
        )

    pattern_html = ""
    if pattern_analysis:
        pattern_html = (
            "<ul>" + "".join([f"<li>{p}</li>" for p in pattern_analysis]) + "</ul>"
        )

    # Generate attack scenario
    attack_scenario = ""
    if in_rockyou:
        attack_scenario = "This password would be cracked <strong>instantly</strong> in a dictionary attack using known breached passwords."
    elif patterns.get("dictionary_word") and patterns.get("number_suffix"):
        attack_scenario = "In a targeted attack, an adversary would likely try dictionary words with common number combinations first, potentially cracking this password within minutes to hours."
    elif patterns.get("keyboard_pattern"):
        attack_scenario = "Keyboard pattern attacks are among the first strategies in password cracking tools, making this password vulnerable to being discovered early in an attack."
    elif entropy < 40:
        attack_scenario = "With modern hardware, brute force attacks could crack this password in a matter of hours to days."

    # Create the HTML response
    html = f"""
    <h3>Password Security Analysis</h3>
    <p>{base_assessment}</p>
    <p>{rockyou_text}</p>
    
    <h3>Pattern Detection</h3>
    {pattern_html if pattern_html else "<p>No significant patterns detected.</p>"}
    
    <h3>Attack Scenario</h3>
    <p>Your risk level is <strong>{risk_level}</strong>. {attack_scenario}</p>
    
    <h3>Recommendation</h3>
    <p>Consider using a password manager to generate and store truly random, high-entropy passwords that are unique for each service.</p>
    """

    return html


def calculate_pattern_data(password):
    """Calculate data for visualization charts"""
    # Character type breakdown
    length = len(password)
    char_types = {
        "lowercase": (
            len(re.findall(r"[a-z]", password)) / length * 100 if length else 0
        ),
        "uppercase": (
            len(re.findall(r"[A-Z]", password)) / length * 100 if length else 0
        ),
        "digits": len(re.findall(r"[0-9]", password)) / length * 100 if length else 0,
        "special": (
            len(re.findall(r"[^a-zA-Z0-9]", password)) / length * 100 if length else 0
        ),
    }

    # Attack vulnerability levels
    attack_vectors = {
        "dictionary": 0,
        "brute_force": 0,
        "pattern_based": 0,
        "targeted_guess": 0,
        "leaked_database": 0,
    }

    # Dictionary attack vulnerability
    if password in common_passwords:
        attack_vectors["leaked_database"] = 100
    else:
        # Dictionary attack calculations
        if re.match(r"^[a-zA-Z]+$", password):
            attack_vectors["dictionary"] = 70

        # Brute force calculations
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"[0-9]", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 33

        # Calculate brute force strength (inverse of vulnerability)
        brute_force_strength = min(
            100, (charset_size * math.log2(max(1, len(password)))) / 7
        )
        attack_vectors["brute_force"] = max(0, 100 - brute_force_strength)

        # Pattern-based vulnerability
        pattern_score = 0
        if re.search(r"(abc|bcd|cde|def|123|234|345|456)", password, re.IGNORECASE):
            pattern_score += 20
        if re.search(r"(qwerty|asdfgh|zxcvbn)", password, re.IGNORECASE):
            pattern_score += 30
        if re.search(r"(.)\1{2,}", password):
            pattern_score += 15
        if re.search(r"\d{4}$", password):
            pattern_score += 15
        if re.search(r"(19|20)\d{2}", password):
            pattern_score += 20

        attack_vectors["pattern_based"] = min(100, pattern_score)

        # Targeted guessing vulnerability
        if len(password) <= 6:
            attack_vectors["targeted_guess"] = 80
        elif password.lower() in ["password", "qwerty", "123456", "admin"]:
            attack_vectors["targeted_guess"] = 100
        else:
            attack_vectors["targeted_guess"] = max(0, 80 - len(password) * 5)

    # Advanced metrics for enhanced visualizations
    advanced_metrics = {
        "entropy_per_char": (
            calculate_entropy(password) / len(password) if len(password) > 0 else 0
        ),
        "char_variety_ratio": (
            len(set(password)) / len(password) if len(password) > 0 else 0
        ),
        "sequential_ratio": (
            len(
                re.findall(
                    r"(abc|bcd|cde|def|123|234|345|456)", password, re.IGNORECASE
                )
            )
            / len(password)
            if len(password) > 0
            else 0
        ),
        "symbol_density": (
            len(re.findall(r"[^a-zA-Z0-9]", password)) / len(password)
            if len(password) > 0
            else 0
        ),
    }

    return {
        "char_types": char_types,
        "attack_vectors": attack_vectors,
        "advanced_metrics": advanced_metrics,
        "password_length": len(password),
    }


if __name__ == "__main__":
    print("Starting Password Analyzer application...")
    with app.app_context():
        # Create database directory if it doesn't exist
        import os

        os.makedirs("instance", exist_ok=True)

        # Create database tables
        db.create_all()
        print("Database tables created or verified.")

        # Check if any users exist
        user_count = User.query.count()
        print(f"Found {user_count} users in the database.")

        # Check if any passwords exist
        password_count = Password.query.count()
        print(f"Found {password_count} saved passwords in the database.")

    # Run the app
    app.run(debug=True)
