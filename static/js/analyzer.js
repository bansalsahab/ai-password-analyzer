// Password Analyzer - Main JS File

document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('passwordInput');
    const togglePassword = document.getElementById('togglePassword');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const loadingIndicator = document.getElementById('loading');
    
    // Setup password visibility toggle
    togglePassword.addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePassword.textContent = type === 'password' ? 'Show' : 'Hide';
    });
    
    // Analyze password on button click
    analyzeBtn.addEventListener('click', function() {
        analyzePassword();
    });
    
    // Analyze on Enter key
    passwordInput.addEventListener('keyup', function(event) {
        if (event.key === 'Enter') {
            analyzePassword();
        }
    });
    
    // Copy improved password functionality
    document.addEventListener('click', function(e) {
        if (e.target && e.target.id === 'copyImproved') {
            const improvedPassword = document.getElementById('improvedPassword').textContent;
            navigator.clipboard.writeText(improvedPassword).then(() => {
                e.target.textContent = 'Copied!';
                setTimeout(() => {
                    e.target.textContent = 'Copy';
                }, 2000);
            });
        }
    });

    // Main password analysis function
    function analyzePassword() {
        const password = passwordInput.value.trim();
        
        if (!password) {
            alert('Please enter a password to analyze');
            return;
        }
        
        // Show loading indicator
        resultsContainer.classList.add('hidden');
        loadingIndicator.classList.remove('hidden');
        
        // Send password to server for analysis
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password: password }),
        })
        .then(response => response.json())
        .then(data => {
            // Hide loading indicator
            loadingIndicator.classList.add('hidden');
            resultsContainer.classList.remove('hidden');
            
            // Update UI with results
            updateResults(data, password);
            
            // Generate and display password mutations
            displayPasswordMutations(password);
        })
        .catch(error => {
            console.error('Error:', error);
            loadingIndicator.classList.add('hidden');
            alert('An error occurred during analysis. Please try again.');
        });
    }
    
    // Update UI with analysis results
    function updateResults(data, originalPassword) {
        // Strength meter
        const scoreValue = document.getElementById('scoreValue');
        const meterFill = document.querySelector('.meter-fill');
        scoreValue.textContent = data.score;
        meterFill.style.width = `${data.score}%`;
        
        // Get human-readable color based on score
        let scoreColor = '#ff4444'; // Red - default/poor
        if (data.score > 80) {
            scoreColor = '#44ff44'; // Green - excellent
        } else if (data.score > 60) {
            scoreColor = '#44ffff'; // Cyan - good
        } else if (data.score > 40) {
            scoreColor = '#ffff44'; // Yellow - fair
        }
        meterFill.style.backgroundColor = scoreColor;
        
        // Improved password
        document.getElementById('improvedPassword').textContent = data.improved_password;
        document.getElementById('improvementReasoning').innerHTML = `<h3>Why This Is Better</h3><p>${data.improvement_reason}</p>`;
        
        // Crack time
        document.getElementById('crackTimeValue').textContent = data.crack_time.human;
        
        // Update crack time table
        const attackTable = document.getElementById('attackTable');
        attackTable.innerHTML = `
            <tr>
                <th>Attack Vector</th>
                <th>Estimated Time</th>
            </tr>
        `;
        
        for (const [attackName, timeValue] of Object.entries(data.crack_time.attack_times)) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${formatAttackName(attackName)}</td>
                <td>${timeValue}</td>
            `;
            attackTable.appendChild(row);
        }
        
        // Show RockYou warning if password is in the database
        const inCommonDbWarning = document.getElementById('inCommonDb');
        if (data.in_common_db) {
            inCommonDbWarning.classList.remove('hidden');
        } else {
            inCommonDbWarning.classList.add('hidden');
        }
        
        // Add future security prediction
        addFutureSecurityPrediction(data.crack_time);
        
        // Entropy
        document.getElementById('entropyValue').textContent = data.entropy.toFixed(2);
        document.getElementById('bitsExplanation').textContent = getBitsExplanation(data.entropy);
        
        // AI Analysis
        document.querySelector('.deepseek-output').innerHTML = data.ai_analysis;
        
        // Vulnerability breakdown
        const vulnBreakdown = document.getElementById('vulnerabilityBreakdown');
        vulnBreakdown.innerHTML = '';
        
        for (const [vulnerability, details] of Object.entries(data.vulnerabilities)) {
            const vulnCard = document.createElement('div');
            vulnCard.className = 'suggestion';
            vulnCard.innerHTML = `
                <h3>${vulnerability}</h3>
                <p>${details.description}</p>
                ${details.severity ? `<div class="warning">Severity: ${details.severity}</div>` : ''}
            `;
            vulnBreakdown.appendChild(vulnCard);
        }
        
        // Visualize password patterns
        visualizePasswordPatterns(originalPassword);
        
        // Update all visualizations with pattern data
        // Add password length to pattern data for chart calculations
        data.pattern_data.password_length = originalPassword.length;
        updateCharts(data.pattern_data);
    }
    
    // Helper for formatting attack vector names
    function formatAttackName(name) {
        return name
            .replace(/_/g, ' ')
            .replace(/\b\w/g, letter => letter.toUpperCase());
    }
    
    // Helper for entropy explanation
    function getBitsExplanation(entropy) {
        if (entropy < 40) return 'Very weak - easily cracked';
        if (entropy < 60) return 'Weak - vulnerable to determined attackers';
        if (entropy < 80) return 'Moderate - sufficient for most personal use';
        if (entropy < 100) return 'Strong - good for sensitive accounts';
        return 'Very strong - excellent security';
    }
    
    // NEW FEATURE: Predictive Security Timeline
    function addFutureSecurityPrediction(crackTimeData) {
        // Only add this feature to the crack time card
        const crackTimeCard = document.querySelector('.crack-time-card');
        
        // Create container if it doesn't exist
        let predictionContainer = document.getElementById('futurePrediction');
        if (!predictionContainer) {
            predictionContainer = document.createElement('div');
            predictionContainer.id = 'futurePrediction';
            predictionContainer.className = 'future-prediction';
            
            // Add to crack time card
            crackTimeCard.appendChild(predictionContainer);
            
            // Add heading
            const heading = document.createElement('h3');
            heading.textContent = 'Future Security Prediction';
            crackTimeCard.insertBefore(heading, predictionContainer);
        }
        
        // Parse human-readable crack time for baseline
        let baselineYears = 0;
        const crackTimeStr = document.getElementById('crackTimeValue').textContent;
        
        if (crackTimeStr.includes('centuries')) {
            baselineYears = parseFloat(crackTimeStr) * 100;
        } else if (crackTimeStr.includes('years')) {
            baselineYears = parseFloat(crackTimeStr);
        } else if (crackTimeStr.includes('months')) {
            baselineYears = parseFloat(crackTimeStr) / 12;
        } else if (crackTimeStr.includes('weeks')) {
            baselineYears = parseFloat(crackTimeStr) / 52;
        } else if (crackTimeStr.includes('days')) {
            baselineYears = parseFloat(crackTimeStr) / 365;
        } else {
            baselineYears = 0; // Instantly crackable
        }
        
        // Calculate future predictions based on Moore's Law (doubling of computing power every ~18 months)
        // This means cracking time is cut in half every 18 months
        const predictions = [
            { year: 'Now (2024)', yearsFromNow: 0, factor: 1 },
            { year: '2025', yearsFromNow: 1, factor: 0.65 },
            { year: '2027', yearsFromNow: 3, factor: 0.35 },
            { year: 'Quantum Era', yearsFromNow: 10, factor: 0.01 }
        ];
        
        // Determine status for each time period
        predictions.forEach(prediction => {
            const adjustedYears = baselineYears * prediction.factor;
            
            if (adjustedYears > 10) {
                prediction.status = 'safe';
                prediction.statusText = 'Safe';
            } else if (adjustedYears > 1) {
                prediction.status = 'at-risk';
                prediction.statusText = 'At Risk';
            } else {
                prediction.status = 'vulnerable';
                prediction.statusText = 'Vulnerable';
            }
            
            // Format the adjusted time
            if (adjustedYears >= 100) {
                prediction.timeText = `${Math.floor(adjustedYears / 100)} centuries`;
            } else if (adjustedYears >= 1) {
                prediction.timeText = `${Math.floor(adjustedYears)} years`;
            } else if (adjustedYears >= 1/12) {
                prediction.timeText = `${Math.floor(adjustedYears * 12)} months`;
            } else if (adjustedYears >= 1/52) {
                prediction.timeText = `${Math.floor(adjustedYears * 52)} weeks`;
            } else if (adjustedYears >= 1/365) {
                prediction.timeText = `${Math.floor(adjustedYears * 365)} days`;
            } else {
                prediction.timeText = 'Instant';
            }
        });
        
        // Create HTML for the prediction timeline
        let html = `
        <p>As computing power increases over time, passwords become easier to crack. 
        Here's how your password security might change in the future:</p>
        <div class="prediction-timeline">
        `;
        
        predictions.forEach(prediction => {
            html += `
            <div class="prediction-point">
                <div class="prediction-year">${prediction.year}</div>
                <div class="prediction-status ${prediction.status}">${prediction.statusText}</div>
                <div class="prediction-time">${prediction.timeText}</div>
            </div>
            `;
        });
        
        html += `<div class="prediction-line"></div></div>`;
        
        html += `<p class="mutation-explanation">This prediction is based on Moore's Law of computing power doubling approximately every 18 months, 
        and the potential future development of quantum computing technology.</p>`;
        
        predictionContainer.innerHTML = html;
    }
    
    // NEW FEATURE: Password pattern visualization
    function visualizePasswordPatterns(password) {
        // Create visualization container if it doesn't exist
        let patternContainer = document.getElementById('patternVisualization');
        if (!patternContainer) {
            patternContainer = document.createElement('div');
            patternContainer.id = 'patternVisualization';
            patternContainer.className = 'pattern-visualization';
            
            const vulnerabilityCard = document.querySelector('.vulnerability-card');
            vulnerabilityCard.insertBefore(patternContainer, vulnerabilityCard.firstChild);
            
            // Add heading
            const heading = document.createElement('h3');
            heading.textContent = 'Password Pattern Analysis';
            vulnerabilityCard.insertBefore(heading, patternContainer);
        }
        
        // Define pattern detection functions
        const patterns = {
            'digits': /\d/g,
            'uppercase': /[A-Z]/g,
            'lowercase': /[a-z]/g,
            'special': /[^a-zA-Z0-9]/g,
            'repeating': /(.)\\1+/g,
            'sequential': /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/gi,
            'keyboard': /(?:qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)/gi
        };
        
        // Create HTML for visualization
        let html = '<div class="pattern-chars">';
        
        for (let i = 0; i < password.length; i++) {
            const char = password[i];
            const classes = [];
            
            // Determine character classes
            if (/\d/.test(char)) classes.push('digit-char');
            if (/[A-Z]/.test(char)) classes.push('uppercase-char');
            if (/[a-z]/.test(char)) classes.push('lowercase-char');
            if (/[^a-zA-Z0-9]/.test(char)) classes.push('special-char');
            
            // Check for patterns in surrounding context
            for (const [patternName, regex] of Object.entries(patterns)) {
                const subStr = password.substring(Math.max(0, i-2), Math.min(password.length, i+3));
                if (regex.test(subStr)) {
                    classes.push(`${patternName}-pattern`);
                    break;
                }
            }
            
            html += `<span class="${classes.join(' ')}">${char}</span>`;
        }
        
        html += '</div>';
        
        // Add legend
        html += `
        <div class="pattern-legend">
            <div><span class="legend-item digit-char"></span> Digits</div>
            <div><span class="legend-item uppercase-char"></span> Uppercase</div>
            <div><span class="legend-item lowercase-char"></span> Lowercase</div>
            <div><span class="legend-item special-char"></span> Special</div>
            <div><span class="legend-item sequential-pattern"></span> Sequential</div>
            <div><span class="legend-item keyboard-pattern"></span> Keyboard Pattern</div>
        </div>
        `;
        
        patternContainer.innerHTML = html;
    }
    
    // NEW FEATURE: Password mutation testing
    function displayPasswordMutations(password) {
        // Create mutations container if it doesn't exist
        let mutationsContainer = document.getElementById('passwordMutations');
        if (!mutationsContainer) {
            mutationsContainer = document.createElement('div');
            mutationsContainer.id = 'passwordMutations';
            mutationsContainer.className = 'password-mutations';
            
            // Add to improvement card
            const improvementCard = document.querySelector('.improvement-card');
            improvementCard.appendChild(mutationsContainer);
            
            // Add heading
            const heading = document.createElement('h3');
            heading.textContent = 'Password Variation Analysis';
            improvementCard.insertBefore(heading, mutationsContainer);
        }
        
        // Generate common mutations
        const mutations = [
            { name: 'Add year', password: `${password}2024` },
            { name: 'Add special char', password: `${password}!` },
            { name: 'Capitalize first letter', password: password.charAt(0).toUpperCase() + password.slice(1) },
            { name: 'Add number at end', password: `${password}123` },
            { name: 'Replace letters with numbers', password: password.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0') }
        ];
        
        // Analyze mutations on the client side (simplified analysis)
        mutations.forEach(mutation => {
            // Simple entropy calculation
            let entropy = 0;
            const length = mutation.password.length;
            
            let charsetSize = 0;
            if (/[a-z]/.test(mutation.password)) charsetSize += 26;
            if (/[A-Z]/.test(mutation.password)) charsetSize += 26;
            if (/[0-9]/.test(mutation.password)) charsetSize += 10;
            if (/[^a-zA-Z0-9]/.test(mutation.password)) charsetSize += 33;
            
            entropy = Math.log2(Math.pow(charsetSize, length));
            mutation.entropy = entropy.toFixed(1);
            
            // Simplified score 
            mutation.score = Math.min(100, Math.floor(entropy * 2));
            
            // Color based on score
            if (mutation.score > 80) {
                mutation.color = '#44ff44';
            } else if (mutation.score > 60) {
                mutation.color = '#44ffff';
            } else if (mutation.score > 40) {
                mutation.color = '#ffff44';
            } else {
                mutation.color = '#ff4444';
            }
        });
        
        // Create HTML table for mutations
        let html = `
        <table class="mutations-table">
            <tr>
                <th>Variation Type</th>
                <th>Modified Password</th>
                <th>Strength</th>
                <th>Entropy</th>
            </tr>
        `;
        
        mutations.forEach(mutation => {
            html += `
            <tr>
                <td>${mutation.name}</td>
                <td><code>${mutation.password}</code></td>
                <td>
                    <div class="mini-meter">
                        <div class="mini-meter-fill" style="width: ${mutation.score}%; background-color: ${mutation.color}"></div>
                    </div>
                </td>
                <td>${mutation.entropy} bits</td>
            </tr>
            `;
        });
        
        html += '</table>';
        html += `<p class="mutation-explanation">Common password variations are often the first things attackers try. 
                Even a strong base password can become vulnerable with predictable modifications.</p>`;
        
        mutationsContainer.innerHTML = html;
    }
}); 