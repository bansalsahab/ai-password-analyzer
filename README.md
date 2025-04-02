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

- **Improved Visualization Layout**: Enhanced chart layout with a responsive 2-column grid that adapts to mobile screens
- **Added Chart Titles**: Each chart now has a clear title for better understanding
- **New Light/Dark Mode Toggle**: Users can switch between dark and light themes for better accessibility and visual comfort
- **Enhanced User Experience**: Better responsive design for all screen sizes

## Key Features

- **Advanced Entropy Analysis**: Calculates Shannon entropy and analyzes character set complexity to determine base security strength
- **Visual Security Dashboard**: Four specialized interactive charts provide visual representations of:
  - Password vulnerability to different attack vectors
  - Character composition analysis
  - Multi-dimensional security profile radar
  - Security degradation forecast over time (accounting for advancing technologies)
- **RockYou Database Check**: Cross-references password against the complete RockYou database (14.3 million leaked passwords) to check for prior exposure
- **AI-Powered Security Analysis**: Utilizes DeepSeek AI to analyze complex patterns and vulnerabilities that traditional algorithms miss
- **Pattern Recognition Engine**: Identifies 15+ common password patterns including keyboard walks, leetspeak, date formats, and more
- **Smart Password Recommendations**: Suggests improved alternatives that balance security with memorability
- **Comprehensive Vulnerability Breakdown**: Provides detailed explanations of identified weaknesses
- **Attack Simulation**: Calculates estimated crack times across multiple attack vectors (dictionary, brute force, pattern-based, etc.)

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
- **Security Analysis**:
  - Shannon entropy algorithms
  - Pattern matching with regex
  - Character set complexity analysis
  - Attack vector simulation
- **Data Sources**:
  - Complete RockYou database (14.3 million leaked passwords)
  - Common password pattern library
- **AI Integration**: DeepSeek AI for advanced pattern analysis

## How to Run

1. Ensure Python 3.6+ is installed on your system
2. Clone this repository to your local machine
3. Navigate to the project directory in your terminal
4. Run the application with: `python app.py`
5. Open your browser and visit: `http://127.0.0.1:5000`

## Screenshots

### Dark Mode
![Dark Mode](/static/images/dark_mode_demo.png)

### Light Mode
![Light Mode](/static/images/light_mode_demo.png)

## Security & Privacy

This tool performs all password analysis locally in your browser and server. Passwords are never stored or transmitted to external services. The application uses industry-standard security practices to ensure user privacy.

## Project Structure

```
password-analyzer/
├── app.py                 # Flask application and backend logic
├── static/                # Static files
│   ├── css/               # CSS stylesheets
│   │   └── styles.css     # Main stylesheet
│   ├── js/                # JavaScript files
│   │   ├── analyzer.js    # Password analysis logic
│   │   ├── charts.js      # Chart visualization
│   │   └── password-generator.js  # Password generation
│   └── images/            # Image assets
├── templates/             # HTML templates
│   └── index.html         # Main application page
└── README.md              # Project documentation
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