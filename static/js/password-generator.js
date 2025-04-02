/**
 * Password Generator - Generates passwords based on time-to-crack thresholds
 */

document.addEventListener('DOMContentLoaded', function() {
    const generateBtn = document.getElementById('generateBtn');
    const thresholdSelect = document.getElementById('crackTimeThreshold');
    const passwordInput = document.getElementById('passwordInput');
    
    // Generate button click handler
    generateBtn.addEventListener('click', function() {
        generatePasswordForThreshold(thresholdSelect.value);
    });
    
    /**
     * Generate a password that meets the selected time-to-crack threshold
     * @param {string} threshold - The selected threshold (instant, seconds, etc.)
     */
    function generatePasswordForThreshold(threshold) {
        // Map thresholds to minimum entropy requirements
        const entropyRequirements = {
            'instant': 20,      // Very weak, for demo only
            'seconds': 30,      // Very weak, for demo only
            'minutes': 40,      // Weak
            'hours': 50,        // Still weak
            'days': 60,         // Moderate
            'months': 70,       // Good
            'years': 80,        // Strong
            'centuries': 100    // Very strong
        };
        
        const requiredEntropy = entropyRequirements[threshold] || 80;
        const password = generatePasswordWithEntropy(requiredEntropy);
        
        // Set the generated password in the input field
        passwordInput.value = password;
        passwordInput.type = 'text'; // Show the password
        
        // Update toggle button text
        const togglePassword = document.getElementById('togglePassword');
        togglePassword.textContent = 'Hide';
        
        // Automatically analyze the generated password
        const analyzeBtn = document.getElementById('analyzeBtn');
        analyzeBtn.click();
    }
    
    /**
     * Generate a password with approximately the specified entropy
     * @param {number} targetEntropy - The desired entropy in bits
     * @return {string} - The generated password
     */
    function generatePasswordWithEntropy(targetEntropy) {
        // Character sets
        const charSets = {
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            digits: '0123456789',
            symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?'
        };
        
        // Select appropriate character sets based on entropy
        let availableCharSets = [];
        if (targetEntropy < 40) {
            // For very low entropy, just use lowercase
            availableCharSets.push(charSets.lowercase);
        } else if (targetEntropy < 60) {
            // For low entropy, use lowercase and digits
            availableCharSets.push(charSets.lowercase, charSets.digits);
        } else if (targetEntropy < 80) {
            // For medium entropy, use lowercase, uppercase, and digits
            availableCharSets.push(charSets.lowercase, charSets.uppercase, charSets.digits);
        } else {
            // For high entropy, use all character sets
            availableCharSets.push(
                charSets.lowercase, 
                charSets.uppercase, 
                charSets.digits, 
                charSets.symbols
            );
        }
        
        // Combine selected character sets
        const allChars = availableCharSets.join('');
        
        // Calculate entropy per character
        const entropyPerChar = Math.log2(allChars.length);
        
        // Calculate required length
        const requiredLength = Math.ceil(targetEntropy / entropyPerChar);
        
        // Generate random characters
        let password = '';
        for (let i = 0; i < requiredLength; i++) {
            const randomIndex = Math.floor(Math.random() * allChars.length);
            password += allChars.charAt(randomIndex);
        }
        
        // Ensure at least one character from each selected set
        if (targetEntropy >= 60) {
            // Get one character from each set and place it at a random position
            for (const charSet of availableCharSets) {
                const randomCharFromSet = charSet.charAt(Math.floor(Math.random() * charSet.length));
                const randomPosition = Math.floor(Math.random() * password.length);
                password = password.substring(0, randomPosition) + 
                           randomCharFromSet + 
                           password.substring(randomPosition + 1);
            }
        }
        
        return password;
    }
    
    // Password entropy estimation for verification
    function calculateApproxEntropy(password) {
        // Count character types in the password
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        
        // Calculate character pool size
        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSymbol) poolSize += 33; // Approximate for common symbols
        
        // Calculate entropy: log2(poolSize^length)
        const length = password.length;
        const entropy = Math.log2(Math.pow(poolSize, length));
        
        return entropy;
    }
}); 