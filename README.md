# AI-Enhanced Password Analyzer Pro

## Project Overview
This application is a state-of-the-art password security analyzer that combines traditional cryptographic analysis with advanced AI techniques to provide comprehensive password security assessments. Unlike simple password strength meters, this analyzer uses sophisticated algorithms and a database of 14.3 million leaked passwords to thoroughly evaluate password security.

The tool helps users understand the specific vulnerabilities in their passwords and provides actionable suggestions for improvement. It visualizes security metrics through interactive charts and offers detailed explanations of potential attack vectors.

## Purpose
With increasing cyber threats, password security remains critical. Many users don't understand what makes a password truly secure beyond basic complexity rules. This tool bridges that gap by:
- Identifying specific vulnerabilities in user passwords
- Explaining potential attack methodologies
- Demonstrating how password security degrades over time due to advancing technology
- Providing AI-enhanced recommendations for creating secure, yet memorable passwords

## Recent Updates

- **Secure User Authentication**: Added signup/login functionality with zero-knowledge encryption for password storage
- **Password Vault**: Users can now save analyzed passwords in an encrypted vault using AES-256
- **Enhanced Session Management**: Improved session persistence across browsers and devices
- **Improved Visualization Layout**: Enhanced chart layout with a responsive 2-column grid that adapts to mobile screens
- **Added Chart Titles**: Each chart now has a clear title for better understanding
- **New Light/Dark Mode Toggle**: Users can switch between dark and light themes for better accessibility and visual comfort
- **Enhanced Password Strength Display**: Visual badges and gauges to display password strength and entropy
- **Improved User Experience**: Better responsive design for all screen sizes

## Key Features

- **Zero-Knowledge Encrypted Password Vault**:
  - Master password is hashed with PBKDF2 and never stored
  - Analyzed passwords are encrypted with AES-256 before storage
  - Encryption key is derived from the master password
  - All encryption/decryption happens client-side for true zero-knowledge security
- **Advanced Entropy Analysis**: Calculates Shannon entropy and analyzes character set complexity to determine base security strength
- **Visual Security Dashboard**: Four specialized interactive charts provide visual representations of:
  - Password vulnerability to different attack vectors
  - Character composition analysis
  - Multi-dimensional security profile radar
  - Security degradation forecast over time (accounting for advancing technologies)
- **RockYou Database Check**: Cross-references password against the complete RockYou database (14.3 million leaked passwords) to check for prior exposure
- **AI-Powered Security Analysis**: Utilizes sophisticated neural networks to analyze complex patterns and vulnerabilities that traditional algorithms miss
- **Pattern Recognition Engine**: Identifies 15+ common password patterns including keyboard walks, leetspeak, date formats, and more
- **Smart Password Recommendations**: Suggests improved alternatives that balance security with memorability
- **Comprehensive Vulnerability Breakdown**: Provides detailed explanations of identified weaknesses
- **Attack Simulation**: Calculates estimated crack times across multiple attack vectors (dictionary, brute force, pattern-based, etc.)
- **Visual Strength Indicators**: Intuitive badges and gauges clearly display password strength and entropy

## How It Works

1. **Input Analysis**: User enters a password for evaluation
2. **Multi-layered Assessment**:
   - Calculates base entropy and character set diversity
   - Checks against leaked password database
   - Identifies common patterns and structures
   - Applies AI analysis to detect subtle vulnerabilities
   - Simulates various attack methods
3. **Visualization & Results**: Generates interactive charts and detailed security metrics
4. **Improvement Suggestions**: Provides specifically tailored recommendations for creating stronger passwords

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript, Chart.js for interactive visualizations
- **Backend**: Flask (Python) for server-side processing and API endpoints
- **Database**: SQLAlchemy with SQLite database (easily configurable for other databases)
- **Authentication**: Flask-Login for session management with enhanced cookie security
- **Encryption**: AES-256 for password encryption with PBKDF2 key derivation
- **Security Analysis**:
  - Shannon entropy algorithms
  - Pattern matching with regex
  - Character set complexity analysis
  - Attack vector simulation
- **Data Sources**:
  - Complete RockYou database (14.3 million leaked passwords)
  - Common password pattern library
- **AI Integration**: Advanced Neural Networks for sophisticated pattern analysis

## How to Run

1. Ensure Python 3.6+ is installed on your system
2. Clone this repository to your local machine
3. Navigate to the project directory in your terminal
4. Install required dependencies: `pip install -r requirements.txt`
5. Initialize the database: `python migrations/create_tables.py`
6. Run the application with: `python app.py`
7. Open your browser and visit: `http://127.0.0.1:5000`

## Screenshots

### Dark Mode
![Dark Mode](/static/images/dark_mode_demo.png)

### Light Mode
![Light Mode](/static/images/light_mode_demo.png)

## Security & Privacy

This application implements true zero-knowledge encryption:

- **Master Password**: Never transmitted or stored in plain text
- **PBKDF2 Key Derivation**: Protects against brute force attacks
- **AES-256 Encryption**: Military-grade encryption for stored passwords
- **Client-Side Decryption**: Passwords are only decrypted in the user's browser
- **Secure Session Management**: CSRF protection and secure session cookies

All password analysis is performed locally in your browser and server. Passwords are never stored or transmitted to external services unless encrypted with your master password.

## Project Structure

```
password-analyzer/
├── app.py                  # Flask application and API routes
├── app/                    # Application package
│   ├── __init__.py         # Package initialization
│   ├── models.py           # Database models
│   ├── forms.py            # WTForms form classes
│   ├── utils/              # Utility functions
│   └── main.py             # Core application logic
├── migrations/             # Database migrations
│   └── create_tables.py    # Database initialization script
├── static/                 # Static files
│   ├── css/                # CSS stylesheets
│   │   └── styles.css      # Main stylesheet
│   ├── js/                 # JavaScript files
│   │   ├── analyzer.js     # Password analysis logic
│   │   ├── charts.js       # Chart visualization
│   │   └── password-generator.js  # Password generation
│   └── images/             # Image assets
├── templates/              # HTML templates
│   ├── index.html          # Main application page
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   └── dashboard.html      # User dashboard/vault page
├── requirements.txt        # Project dependencies
└── README.md               # Project documentation
```

## Future Enhancements

- Machine learning model to predict password uniqueness
- Quantum computing resistance estimator
- Password manager integration
- Additional language support
- Progressive web app capabilities

## Acknowledgments

- The Flask team for the web framework
- Chart.js for visualization capabilities
- The security research community for password analysis methodologies 