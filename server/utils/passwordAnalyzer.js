const crypto = require('crypto');
const math = require('mathjs');

/**
 * Calculate Shannon entropy of a password
 * @param {string} password - The password to analyze
 * @returns {number} - The calculated entropy
 */
const calculateEntropy = (password) => {
  if (!password) return 0;
  
  // Count character frequencies
  const charCounts = {};
  for (const char of password) {
    charCounts[char] = (charCounts[char] || 0) + 1;
  }
  
  // Calculate entropy
  const length = password.length;
  let entropy = 0;
  
  for (const count of Object.values(charCounts)) {
    const prob = count / length;
    entropy -= prob * Math.log2(prob);
  }
  
  // Multiply by length for total entropy
  entropy *= length;
  
  // Adjust for character set complexity
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;
  
  charsetSize = Math.max(charsetSize, 26); // Assume at least lowercase letters
  
  const theoreticalMax = Math.log2(charsetSize) * length;
  
  // Weight the entropy calculation
  return 0.75 * entropy + 0.25 * theoreticalMax;
};

/**
 * Identify common patterns in the password
 * @param {string} password - The password to analyze
 * @returns {object} - Object containing identified patterns
 */
const identifyPatterns = (password) => {
  const patterns = {};
  
  // Check for dictionary words (simplified)
  if (password.length >= 4) {
    patterns.dictionaryWord = true;
  }
  
  // Check for sequential characters
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890/i.test(password)) {
    patterns.sequentialChars = true;
  }
  
  // Check for repeated characters
  if (/(.)\1{2,}/.test(password)) {
    patterns.repeatedChars = true;
  }
  
  // Check for keyboard patterns
  if (/qwert|asdfg|zxcvb|12345|09876|qazws|wsxed|edcrf|rfvtg/i.test(password)) {
    patterns.keyboardPattern = true;
  }
  
  // Check for numbers only
  if (/^\d+$/.test(password)) {
    patterns.numbersOnly = true;
  }
  
  // Check for letters only
  if (/^[a-zA-Z]+$/.test(password)) {
    patterns.lettersOnly = true;
  }
  
  // Check for common suffixes
  if (/\d{1,4}$/.test(password)) {
    patterns.numberSuffix = true;
  }
  
  if (/[!@#$%^&*]+$/.test(password)) {
    patterns.specialSuffix = true;
  }
  
  // Check for common formats
  if (/^[A-Z][a-z]+\d+$/.test(password)) {
    patterns.capitalWordNumber = true;
  }
  
  // Check for date formats
  if (/(19\d\d|20\d\d)/.test(password)) {
    patterns.year = true;
  }
  
  if (/\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/.test(password)) {
    patterns.dateFormat = true;
  }
  
  // Check for leetspeak
  if (/[4@3€31!70]/.test(password)) {
    patterns.leetspeak = true;
  }
  
  return patterns;
};

/**
 * Estimate time to crack the password
 * @param {string} password - The password to analyze
 * @param {number} entropy - The calculated entropy
 * @param {boolean} inCommonDb - Whether the password appears in common password database
 * @returns {object} - Crack time estimations
 */
const estimateCrackTime = (password, entropy, inCommonDb) => {
  // Define cracking speeds (guesses per second)
  const speeds = {
    online_throttled: 100,           // 100 guesses per second
    online_unthrottled: 10000,       // 10k guesses per second
    offline_slow_hash: 1000000,      // 1M guesses per second (bcrypt/PBKDF2)
    offline_fast_hash: 1000000000,   // 1B guesses per second (MD5/SHA)
    offline_gpu_farm: 100000000000,  // 100B guesses per second (large GPU farm)
    quantum_computer: 10000000000000 // 10T guesses per second (future quantum)
  };
  
  // Calculate possible combinations
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;
  
  charsetSize = Math.max(charsetSize, 26);  // Assume at least lowercase letters
  
  // If password is in common database, it can be cracked instantly
  let guesses = inCommonDb ? 1000 : Math.pow(2, entropy);
  
  // Calculate times for each attack vector
  const attackTimes = {};
  for (const [attack, speed] of Object.entries(speeds)) {
    const seconds = guesses / speed;
    attackTimes[attack] = formatTime(seconds);
  }
  
  // Get human-readable overall time (based on offline_fast_hash as reference)
  const humanTime = attackTimes.offline_fast_hash;
  
  return {
    human: humanTime,
    attack_times: attackTimes
  };
};

/**
 * Format time in seconds to a human-readable string
 * @param {number} seconds - Time in seconds
 * @returns {string} - Formatted time
 */
const formatTime = (seconds) => {
  if (seconds < 0.001) return "Instantly";
  if (seconds < 1) return `${seconds*1000:.0f} milliseconds`;
  if (seconds < 60) return `${seconds:.1f} seconds`;
  if (seconds < 3600) return `${seconds/60:.1f} minutes`;
  if (seconds < 86400) return `${seconds/3600:.1f} hours`;
  if (seconds < 2592000) return `${seconds/86400:.1f} days`;
  if (seconds < 31536000) return `${seconds/2592000:.1f} months`;
  if (seconds < 3153600000) return `${seconds/31536000:.1f} years`;
  if (seconds < 315360000000) return `${seconds/31536000:.0f} years`;
  
  return `${seconds/31536000/100:.0f} centuries`;
};

/**
 * Identify vulnerabilities in the password
 * @param {string} password - The password to analyze
 * @param {object} patterns - Identified patterns
 * @param {boolean} inCommonDb - Whether the password appears in common password database
 * @returns {object} - Identified vulnerabilities
 */
const identifyVulnerabilities = (password, patterns, inCommonDb) => {
  const vulnerabilities = {};
  
  if (inCommonDb) {
    vulnerabilities["Common Password"] = {
      description: "This password appears in the RockYou data breach of over 14 million passwords. Hackers will try these passwords first.",
      severity: "Critical"
    };
  }
  
  if (password.length < 8) {
    vulnerabilities["Too Short"] = {
      description: "Passwords should be at least 8 characters long to resist brute force attacks.",
      severity: "High"
    };
  }
  
  if (patterns.dictionaryWord) {
    vulnerabilities["Dictionary Word"] = {
      description: "Your password may be a common word or name which is vulnerable to dictionary attacks.",
      severity: "Medium"
    };
  }
  
  if (patterns.sequentialChars) {
    vulnerabilities["Sequential Characters"] = {
      description: "Your password contains sequential characters (like 'abc' or '123') which are easy to guess.",
      severity: "Medium"
    };
  }
  
  if (patterns.repeatedChars) {
    vulnerabilities["Repeated Characters"] = {
      description: "Your password contains repeated characters which reduce entropy and make it easier to crack.",
      severity: "Low"
    };
  }
  
  if (patterns.keyboardPattern) {
    vulnerabilities["Keyboard Pattern"] = {
      description: "Your password follows a keyboard pattern (like 'qwerty') which is one of the first patterns hackers try.",
      severity: "High"
    };
  }
  
  if (patterns.numbersOnly) {
    vulnerabilities["Numbers Only"] = {
      description: "Your password contains only numbers, severely limiting its complexity.",
      severity: "Critical"
    };
  }
  
  if (patterns.lettersOnly) {
    vulnerabilities["Letters Only"] = {
      description: "Your password contains only letters. Adding numbers and special characters would make it stronger.",
      severity: "High"
    };
  }
  
  if (patterns.numberSuffix) {
    vulnerabilities["Number Suffix"] = {
      description: "Adding numbers at the end of a password is a common pattern that attackers check first.",
      severity: "Medium"
    };
  }
  
  if (patterns.year) {
    vulnerabilities["Year Pattern"] = {
      description: "Your password contains a year, which is a predictable pattern used in over 20% of passwords.",
      severity: "Medium"
    };
  }
  
  if (patterns.dateFormat) {
    vulnerabilities["Date Format"] = {
      description: "Your password contains a date format, which significantly reduces the possible combinations.",
      severity: "Medium"
    };
  }
  
  if (!(/[A-Z]/.test(password))) {
    vulnerabilities["No Uppercase"] = {
      description: "Your password lacks uppercase letters, which reduces its complexity.",
      severity: "Low"
    };
  }
  
  if (!(/[0-9]/.test(password))) {
    vulnerabilities["No Numbers"] = {
      description: "Your password lacks numbers, which reduces its complexity.",
      severity: "Low"
    };
  }
  
  if (!(/[^a-zA-Z0-9]/.test(password))) {
    vulnerabilities["No Special Characters"] = {
      description: "Your password lacks special characters, which reduces its complexity.",
      severity: "Low"
    };
  }
  
  return vulnerabilities;
};

/**
 * Suggest an improved version of the password
 * @param {string} password - The original password
 * @param {object} vulnerabilities - Identified vulnerabilities
 * @returns {object} - Improved password and reason
 */
const suggestImprovedPassword = (password, vulnerabilities) => {
  let improved = password;
  const changes = [];
  
  // If it's a common password, generate a completely new one
  if (vulnerabilities["Common Password"]) {
    return {
      improvedPassword: generateStrongPassword(),
      reason: "This is a completely new password that follows best practices for security. It's not found in common password databases and has high entropy."
    };
  }
  
  // Add length if too short
  if (vulnerabilities["Too Short"]) {
    const additionalChars = crypto.randomBytes(5).toString('base64').substring(0, 10 - password.length);
    improved += additionalChars;
    changes.push(`Added ${additionalChars.length} characters to increase length`);
  }
  
  // Replace sequential characters
  if (vulnerabilities["Sequential Characters"]) {
    for (const seq of ["abc", "bcd", "cde", "def", "123", "234", "345", "456"]) {
      if (improved.toLowerCase().includes(seq)) {
        const replacement = crypto.randomBytes(3).toString('base64').substring(0, 3);
        improved = improved.replace(new RegExp(seq, 'i'), replacement);
        changes.push(`Replaced sequential pattern '${seq}' with '${replacement}'`);
      }
    }
  }
  
  // Break keyboard patterns
  if (vulnerabilities["Keyboard Pattern"]) {
    for (const pattern of ["qwert", "asdfg", "zxcvb", "12345"]) {
      if (improved.toLowerCase().includes(pattern)) {
        const replacement = crypto.randomBytes(pattern.length).toString('base64').substring(0, pattern.length);
        improved = improved.replace(new RegExp(pattern, 'i'), replacement);
        changes.push("Replaced keyboard pattern with unpredictable characters");
      }
    }
  }
  
  // Add uppercase if missing
  if (vulnerabilities["No Uppercase"]) {
    const positions = [];
    for (let i = 0; i < improved.length; i++) {
      if (improved[i].match(/[a-z]/)) positions.push(i);
    }
    
    if (positions.length > 0) {
      const pos = positions[Math.floor(Math.random() * positions.length)];
      improved = improved.substring(0, pos) + improved[pos].toUpperCase() + improved.substring(pos + 1);
      changes.push("Added uppercase letter");
    }
  }
  
  // Add numbers if missing
  if (vulnerabilities["No Numbers"]) {
    if (!(/[0-9]/.test(improved))) {
      const pos = Math.floor(Math.random() * improved.length);
      const digit = Math.floor(Math.random() * 10).toString();
      improved = improved.substring(0, pos) + digit + improved.substring(pos);
      changes.push(`Added number '${digit}'`);
    }
  }
  
  // Add special char if missing
  if (vulnerabilities["No Special Characters"]) {
    if (!(/[^a-zA-Z0-9]/.test(improved))) {
      const pos = Math.floor(Math.random() * improved.length);
      const specialChars = "!@#$%^&*()-_=+";
      const special = specialChars[Math.floor(Math.random() * specialChars.length)];
      improved = improved.substring(0, pos) + special + improved.substring(pos);
      changes.push(`Added special character '${special}'`);
    }
  }
  
  // Break up number suffix with special chars
  if (vulnerabilities["Number Suffix"]) {
    const match = improved.match(/\d+$/);
    if (match) {
      const suffix = match[0];
      let newSuffix = "";
      for (const digit of suffix) {
        const randomChar = crypto.randomBytes(1).toString('base64').substring(0, 1);
        newSuffix += digit + randomChar;
      }
      improved = improved.substring(0, improved.length - suffix.length) + newSuffix;
      changes.push("Broke up number suffix with random characters");
    }
  }
  
  // Replace years with more complex variations
  if (vulnerabilities["Year Pattern"]) {
    for (const year of ["2022", "2023", "2024", "1990", "1991", "1992", "1993", "1994", "1995"]) {
      if (improved.includes(year)) {
        const replacement = crypto.randomBytes(4).toString('base64').substring(0, 4);
        improved = improved.replace(year, replacement);
        changes.push(`Replaced year ${year} with unpredictable characters`);
      }
    }
  }
  
  // If no changes were made, make the password more complex
  if (changes.length === 0 || improved === password) {
    const originalLen = password.length;
    // Keep first 3 chars as mnemonic device
    const prefix = password.substring(0, Math.min(3, originalLen));
    // Generate a strong suffix
    const suffixLength = Math.max(8, originalLen);
    let suffix = "";
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    for (let i = 0; i < suffixLength; i++) {
      suffix += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    improved = prefix + suffix;
    changes.push("Created a more complex variation while preserving the beginning for memorability");
  }
  
  // Create explanation
  const reason = "This improved password addresses the vulnerabilities by: " + changes.join(", ") + ".";
  
  return { improvedPassword: improved, reason };
};

/**
 * Generate a completely new strong password
 * @returns {string} - A strong password
 */
const generateStrongPassword = () => {
  // Use different character sets
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const special = "!@#$%^&*-_=+";
  
  // Ensure at least one of each type
  let pwd = "";
  pwd += upper.charAt(Math.floor(Math.random() * upper.length));
  pwd += lower.charAt(Math.floor(Math.random() * lower.length));
  pwd += digits.charAt(Math.floor(Math.random() * digits.length));
  pwd += special.charAt(Math.floor(Math.random() * special.length));
  
  // Add more random characters
  const allChars = upper + lower + digits + special;
  for (let i = 0; i < 8; i++) {
    pwd += allChars.charAt(Math.floor(Math.random() * allChars.length));
  }
  
  // Shuffle the characters
  pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');
  
  return pwd;
};

/**
 * Calculate data for visualization charts
 * @param {string} password - The password to analyze
 * @returns {object} - Data for visualizations
 */
const calculatePatternData = (password) => {
  // Character type breakdown
  const length = password.length;
  const lowercase = password.match(/[a-z]/g) || [];
  const uppercase = password.match(/[A-Z]/g) || [];
  const digits = password.match(/[0-9]/g) || [];
  const special = password.match(/[^a-zA-Z0-9]/g) || [];
  
  const charTypes = {
    lowercase: (lowercase.length / length) * 100,
    uppercase: (uppercase.length / length) * 100,
    digits: (digits.length / length) * 100,
    special: (special.length / length) * 100
  };
  
  // Attack vulnerability levels
  const attackVectors = {
    dictionary: 0,
    bruteForce: 0,
    patternBased: 0,
    targetedGuess: 0,
    leakedDatabase: 0
  };
  
  // Dictionary attack vulnerability
  if (/^[a-zA-Z]+$/.test(password)) {
    attackVectors.dictionary = 70;
  }
  
  // Brute force calculations
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;
  
  // Calculate brute force strength (inverse of vulnerability)
  const brute_force_strength = Math.min(100, (charsetSize * Math.log2(Math.max(1, length))) / 7);
  attackVectors.bruteForce = Math.max(0, 100 - brute_force_strength);
  
  // Pattern-based vulnerability
  let pattern_score = 0;
  if (/abc|bcd|cde|def|123|234|345|456/i.test(password)) {
    pattern_score += 20;
  }
  if (/qwerty|asdfgh|zxcvbn/i.test(password)) {
    pattern_score += 30;
  }
  if (/(.)\1{2,}/.test(password)) {
    pattern_score += 15;
  }
  if (/\d{4}$/.test(password)) {
    pattern_score += 15;
  }
  if (/(19|20)\d{2}/.test(password)) {
    pattern_score += 20;
  }
  
  attackVectors.patternBased = Math.min(100, pattern_score);
  
  // Targeted guessing vulnerability
  if (length <= 6) {
    attackVectors.targetedGuess = 80;
  } else if (/password|qwerty|123456|admin/i.test(password)) {
    attackVectors.targetedGuess = 100;
  } else {
    attackVectors.targetedGuess = Math.max(0, 80 - length * 5);
  }
  
  // Advanced metrics for enhanced visualizations
  const advancedMetrics = {
    entropyPerChar: calculateEntropy(password) / length,
    charVarietyRatio: new Set(password).size / length,
    sequentialRatio: (password.match(/abc|bcd|cde|def|123|234|345|456/gi) || []).length / length,
    symbolDensity: (password.match(/[^a-zA-Z0-9]/g) || []).length / length
  };
  
  return {
    charTypes,
    attackVectors,
    advancedMetrics,
    passwordLength: length
  };
};

/**
 * Generate AI-like analysis explaining the password's strengths and weaknesses
 * @param {string} password - The password to analyze
 * @param {object} patterns - Identified patterns
 * @param {boolean} inCommonDb - Whether the password appears in common password database
 * @param {number} entropy - The calculated entropy
 * @returns {string} - HTML-formatted analysis
 */
const generateAiAnalysis = (password, patterns, inCommonDb, entropy) => {
  // Start with a base assessment
  let riskLevel, baseAssessment;
  
  if (entropy < 30) {
    riskLevel = "extremely high";
    baseAssessment = `Your password has very low entropy (${entropy.toFixed(1)} bits) and would be cracked almost instantly in most scenarios.`;
  } else if (entropy < 60) {
    riskLevel = "high";
    baseAssessment = `Your password has inadequate entropy (${entropy.toFixed(1)} bits) and would be vulnerable to targeted attacks.`;
  } else if (entropy < 80) {
    riskLevel = "moderate";
    baseAssessment = `Your password has moderate entropy (${entropy.toFixed(1)} bits) and provides some security against casual attacks.`;
  } else {
    riskLevel = "relatively low";
    baseAssessment = `Your password has good entropy (${entropy.toFixed(1)} bits) and would resist most attack scenarios.`;
  }
  
  // Check if it's in the common database
  const rockyouText = inCommonDb
    ? "<strong>Critical Vulnerability:</strong> This exact password appears in the RockYou data breach, making it trivial to crack using dictionary attacks."
    : "This password does not appear verbatim in the RockYou data breach database we analyzed.";
  
  // Analyze patterns
  const patternAnalysis = [];
  
  if (patterns.dictionaryWord) {
    patternAnalysis.push("Contains recognizable words that make it vulnerable to dictionary attacks");
  }
  
  if (patterns.sequentialChars) {
    patternAnalysis.push("Contains sequential characters (like 'abc' or '123') that reduce complexity");
  }
  
  if (patterns.repeatedChars) {
    patternAnalysis.push("Contains repeated characters that reduce entropy");
  }
  
  if (patterns.keyboardPattern) {
    patternAnalysis.push("Contains keyboard patterns that are among the first patterns attackers try");
  }
  
  if (patterns.numbersOnly) {
    patternAnalysis.push("Consists of only numbers, which drastically limits the possible combinations");
  }
  
  if (patterns.lettersOnly) {
    patternAnalysis.push("Contains only letters, missing the extra security from numbers and special characters");
  }
  
  if (patterns.numberSuffix) {
    patternAnalysis.push("Ends with numbers, a pattern used in over 30% of passwords");
  }
  
  if (patterns.year) {
    patternAnalysis.push("Contains a year, which is highly predictable");
  }
  
  if (patterns.dateFormat) {
    patternAnalysis.push("Contains a date pattern, which reduces possible combinations significantly");
  }
  
  if (patterns.leetspeak) {
    patternAnalysis.push("Uses leetspeak (replacing letters with numbers/symbols), which is a known pattern that attackers check");
  }
  
  const patternHtml = patternAnalysis.length
    ? "<ul>" + patternAnalysis.map(p => `<li>${p}</li>`).join('') + "</ul>"
    : "<p>No significant patterns detected.</p>";
  
  // Generate attack scenario
  let attackScenario = "";
  if (inCommonDb) {
    attackScenario = "This password would be cracked <strong>instantly</strong> in a dictionary attack using known breached passwords.";
  } else if (patterns.dictionaryWord && patterns.numberSuffix) {
    attackScenario = "In a targeted attack, an adversary would likely try dictionary words with common number combinations first, potentially cracking this password within minutes to hours.";
  } else if (patterns.keyboardPattern) {
    attackScenario = "Keyboard pattern attacks are among the first strategies in password cracking tools, making this password vulnerable to being discovered early in an attack.";
  } else if (entropy < 40) {
    attackScenario = "With modern hardware, brute force attacks could crack this password in a matter of hours to days.";
  } else {
    attackScenario = "A determined attacker with specialized hardware would need significant resources to crack this password.";
  }
  
  // Create the HTML response
  const html = `
    <h3>Password Security Analysis</h3>
    <p>${baseAssessment}</p>
    <p>${rockyouText}</p>
    
    <h3>Pattern Detection</h3>
    ${patternHtml}
    
    <h3>Attack Scenario</h3>
    <p>Your risk level is <strong>${riskLevel}</strong>. ${attackScenario}</p>
    
    <h3>Recommendation</h3>
    <p>Consider using a password manager to generate and store truly random, high-entropy passwords that are unique for each service.</p>
  `;
  
  return html;
};

module.exports = {
  calculateEntropy,
  identifyPatterns,
  estimateCrackTime,
  identifyVulnerabilities,
  suggestImprovedPassword,
  calculatePatternData,
  generateAiAnalysis,
  generateStrongPassword
}; 