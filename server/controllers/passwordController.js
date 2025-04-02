const asyncHandler = require('express-async-handler');
const Password = require('../models/passwordModel');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { 
  calculateEntropy, 
  identifyPatterns, 
  estimateCrackTime, 
  identifyVulnerabilities, 
  suggestImprovedPassword, 
  calculatePatternData,
  generateAiAnalysis
} = require('../utils/passwordAnalyzer');

// Global variables for RockYou dataset
let commonPasswords = new Set();
let commonPatterns = {};

// @desc    Load RockYou dataset
// @route   None (internal function)
// @access  Private
const loadRockYouDataset = () => {
  try {
    const rockyouPath = process.env.ROCKYOU_PATH || path.join(__dirname, '../../data/rockyou.txt');
    
    console.log(`Loading RockYou dataset from ${rockyouPath}...`);
    
    if (!fs.existsSync(rockyouPath)) {
      console.error(`RockYou dataset not found at ${rockyouPath}`);
      return;
    }
    
    const data = fs.readFileSync(rockyouPath, 'utf8');
    const passwords = data.split('\n').map(p => p.trim()).filter(p => p);
    
    commonPasswords = new Set(passwords);
    
    // Extract pattern statistics from a sample
    const sampleSize = Math.min(500000, passwords.length);
    const sample = passwords.slice(0, sampleSize);
    
    // Calculate pattern frequencies
    const patterns = {
      numbers_suffix: 0,
      special_suffix: 0,
      capital_first: 0,
      leetspeak: 0,
      keyboard_walks: 0,
      year_patterns: 0
    };
    
    // Regular expressions for pattern detection
    const regexes = {
      numbers_suffix: /\d+$/,
      special_suffix: /[!@#$%^&*]+$/,
      capital_first: /^[A-Z]/,
      leetspeak: /[4@3€31!70]/,
      keyboard_walks: /(qwer|asdf|zxcv|1234|wasd)/i,
      year_patterns: /(19\d\d|20\d\d)/
    };
    
    // Count occurrences
    for (const password of sample) {
      for (const [patternName, regex] of Object.entries(regexes)) {
        if (regex.test(password)) {
          patterns[patternName]++;
        }
      }
    }
    
    // Convert to percentages
    for (const pattern in patterns) {
      patterns[pattern] = (patterns[pattern] / sampleSize) * 100;
    }
    
    commonPatterns = patterns;
    
    console.log(`Loaded ${commonPasswords.size} passwords from RockYou dataset`);
    console.log(`Pattern analysis: ${JSON.stringify(commonPatterns)}`);
  } catch (error) {
    console.error(`Error loading RockYou dataset: ${error.message}`);
  }
};

// Load dataset on startup
loadRockYouDataset();

// @desc    Analyze password
// @route   POST /api/passwords/analyze
// @access  Public
const analyzePassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    res.status(400);
    throw new Error('Password is required');
  }
  
  // Basic entropy calculation
  const entropy = calculateEntropy(password);
  
  // Check if password is in RockYou database
  const inCommonDb = commonPasswords.has(password);
  
  // Identify patterns
  const patterns = identifyPatterns(password);
  
  // Calculate crack time
  const crackTime = estimateCrackTime(password, entropy, inCommonDb);
  
  // Identify vulnerabilities
  const vulnerabilities = identifyVulnerabilities(password, patterns, inCommonDb);
  
  // Calculate score
  const score = calculateScore(password, entropy, patterns, inCommonDb);
  
  // Suggest improved password
  const { improvedPassword, reason } = suggestImprovedPassword(password, vulnerabilities);
  
  // Calculate pattern data for visualization
  const patternData = calculatePatternData(password);
  
  // Generate AI analysis
  const aiAnalysis = generateAiAnalysis(password, patterns, inCommonDb, entropy);
  
  // Create response object
  const analysis = {
    score,
    entropy,
    crack_time: crackTime,
    in_common_db: inCommonDb,
    patterns,
    ai_analysis: aiAnalysis,
    vulnerabilities,
    improved_password: improvedPassword,
    improvement_reason: reason,
    pattern_data: patternData
  };
  
  // Save analysis if user is logged in
  if (req.user) {
    // Create a hash of the password for storage
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    
    // Convert vulnerabilities to array format for DB
    const vulnArray = Object.entries(vulnerabilities).map(([name, details]) => ({
      name,
      description: details.description,
      severity: details.severity
    }));
    
    // Save password analysis to database
    await Password.create({
      user: req.user._id,
      passwordHash,
      score,
      entropy,
      crackTime: {
        human: crackTime.human,
        attackTimes: {
          onlineThrottled: crackTime.attack_times.online_throttled,
          onlineUnthrottled: crackTime.attack_times.online_unthrottled,
          offlineSlowHash: crackTime.attack_times.offline_slow_hash,
          offlineFastHash: crackTime.attack_times.offline_fast_hash,
        }
      },
      inCommonDb,
      patterns,
      improvedPassword,
      vulnerabilities: vulnArray,
      patternData
    });
  }
  
  res.json(analysis);
});

// @desc    Get user's password history
// @route   GET /api/passwords/history
// @access  Private
const getPasswordHistory = asyncHandler(async (req, res) => {
  const passwords = await Password.find({ user: req.user._id }).sort({ createdAt: -1 });
  
  res.json(passwords);
});

// Calculate overall password score
const calculateScore = (password, entropy, patterns, inRockyou) => {
  let score = 0;
  
  // Base score from entropy (max 70 points)
  score += Math.min(70, entropy);
  
  // Length bonus (max 10 points)
  const length = password.length;
  if (length >= 12) {
    score += 10;
  } else if (length >= 8) {
    score += 5;
  }
  
  // Character set diversity (max 10 points)
  let charSetScore = 0;
  if (/[a-z]/.test(password)) charSetScore += 2.5;
  if (/[A-Z]/.test(password)) charSetScore += 2.5;
  if (/[0-9]/.test(password)) charSetScore += 2.5;
  if (/[^a-zA-Z0-9]/.test(password)) charSetScore += 2.5;
  score += charSetScore;
  
  // Penalize for patterns (max -30 points)
  let patternPenalty = 0;
  if (patterns.dictionaryWord) patternPenalty += 5;
  if (patterns.sequentialChars) patternPenalty += 5;
  if (patterns.repeatedChars) patternPenalty += 5;
  if (patterns.keyboardPattern) patternPenalty += 10;
  if (patterns.numbersOnly) patternPenalty += 15;
  if (patterns.lettersOnly) patternPenalty += 10;
  if (patterns.numberSuffix) patternPenalty += 3;
  if (patterns.specialSuffix) patternPenalty += 2;
  if (patterns.year) patternPenalty += 5;
  if (patterns.dateFormat) patternPenalty += 8;
  
  // Cap the penalty
  patternPenalty = Math.min(30, patternPenalty);
  score -= patternPenalty;
  
  // Severe penalty if password is in RockYou dataset (-40 points)
  if (inRockyou) {
    score -= 40;
  }
  
  return Math.max(0, Math.min(100, Math.round(score)));
};

module.exports = {
  analyzePassword,
  getPasswordHistory,
}; 