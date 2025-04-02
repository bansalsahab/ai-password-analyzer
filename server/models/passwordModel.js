const mongoose = require('mongoose');

const passwordSchema = mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    // We store a hash of the password, not the actual password
    passwordHash: {
      type: String,
      required: true,
    },
    score: {
      type: Number,
      required: true,
    },
    entropy: {
      type: Number,
      required: true,
    },
    crackTime: {
      human: String,
      attackTimes: {
        onlineThrottled: String,
        onlineUnthrottled: String,
        offlineSlowHash: String,
        offlineFastHash: String,
      },
    },
    inCommonDb: {
      type: Boolean,
      default: false,
    },
    patterns: {
      dictionaryWord: Boolean,
      sequentialChars: Boolean,
      repeatedChars: Boolean,
      keyboardPattern: Boolean,
      numbersOnly: Boolean,
      lettersOnly: Boolean,
      numberSuffix: Boolean,
      specialSuffix: Boolean,
      year: Boolean,
      dateFormat: Boolean,
      leetspeak: Boolean,
    },
    improvedPassword: {
      type: String,
    },
    vulnerabilities: [
      {
        name: String,
        description: String,
        severity: String,
      }
    ],
    patternData: {
      charTypes: {
        lowercase: Number,
        uppercase: Number,
        digits: Number,
        special: Number,
      },
      attackVectors: {
        dictionary: Number,
        bruteForce: Number,
        patternBased: Number,
        targetedGuess: Number,
        leakedDatabase: Number,
      },
    },
  },
  {
    timestamps: true,
  }
);

const Password = mongoose.model('Password', passwordSchema);

module.exports = Password; 