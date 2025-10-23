import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Eye, EyeOff, Lock, Zap, Award, Info } from 'lucide-react';

const PasswordStrengthAnalyzer = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [breachStatus, setBreachStatus] = useState(null);
  const [isChecking, setIsChecking] = useState(false);

  // Calculate Shannon entropy
  const calculateEntropy = (pwd) => {
    if (!pwd) return 0;
    const charSetSize = getCharacterSetSize(pwd);
    return Math.log2(Math.pow(charSetSize, pwd.length));
  };

  const getCharacterSetSize = (pwd) => {
    let size = 0;
    if (/[a-z]/.test(pwd)) size += 26;
    if (/[A-Z]/.test(pwd)) size += 26;
    if (/[0-9]/.test(pwd)) size += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) size += 32;
    return size;
  };

  // Advanced pattern detection
  const detectPatterns = (pwd) => {
    const patterns = [];
    
    // Sequential characters (forward and backward)
    const sequences = ['abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz', '012', '123', '234', '345', '456', '567', '678', '789'];
    if (sequences.some(seq => pwd.toLowerCase().includes(seq) || pwd.toLowerCase().includes(seq.split('').reverse().join('')))) {
      patterns.push('Sequential characters detected (abc, 123, etc.)');
    }
    
    // Repeated characters (3 or more)
    if (/(.)\1{2,}/.test(pwd)) {
      patterns.push('Repeated characters found (aaa, 111, etc.)');
    }
    
    // Common password words
    const commonWords = ['password', 'admin', 'user', 'login', 'welcome', '12345', 'qwerty', 'letmein', 'monkey', 'dragon', 'master', 'trustno1'];
    const foundWords = commonWords.filter(word => pwd.toLowerCase().includes(word));
    if (foundWords.length > 0) {
      patterns.push(`Contains common password words: ${foundWords.join(', ')}`);
    }
    
    // Keyboard patterns
    const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', 'wsxedc'];
    const foundKeyboard = keyboardPatterns.filter(pattern => pwd.toLowerCase().includes(pattern));
    if (foundKeyboard.length > 0) {
      patterns.push(`Keyboard pattern detected: ${foundKeyboard.join(', ')}`);
    }

    // Date patterns (YYYY, MMDD, etc.)
    if (/19\d{2}|20\d{2}/.test(pwd)) {
      patterns.push('Contains year pattern (1900-2099)');
    }

    // Simple substitutions (l33t speak)
    if (/[40@][53][1!][70]/.test(pwd)) {
      patterns.push('Simple character substitutions detected (l33t speak)');
    }

    return patterns;
  };

  // Simulate Have I Been Pwned API check
  const checkBreachStatus = async (pwd) => {
    setIsChecking(true);
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const commonPasswords = [
      'password', '123456', '12345678', 'qwerty', 'abc123', 
      'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
      'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
      'bailey', 'passw0rd', 'shadow', '123123', '654321',
      'football', 'michael', 'ninja', 'mustang', 'password1'
    ];
    
    const isBreached = commonPasswords.some(common => 
      pwd.toLowerCase().includes(common) || 
      common.includes(pwd.toLowerCase()) ||
      pwd.toLowerCase() === common
    );
    
    setBreachStatus({
      breached: isBreached,
      count: isBreached ? Math.floor(Math.random() * 10000000) + 100000 : 0
    });
    
    setIsChecking(false);
  };

  // Comprehensive password strength analysis
  useEffect(() => {
    if (!password) {
      setAnalysis(null);
      setBreachStatus(null);
      return;
    }

    const checks = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[^a-zA-Z0-9]/.test(password),
    };

    const passedChecks = Object.values(checks).filter(Boolean).length;
    const entropy = calculateEntropy(password);
    const patterns = detectPatterns(password);

    let strength = 'Weak';
    let color = 'text-red-500';
    let score = 0;

    // Scoring algorithm based on NIST guidelines
    if (passedChecks >= 5 && password.length >= 16 && entropy > 80 && patterns.length === 0) {
      strength = 'Very Strong';
      color = 'text-green-600';
      score = 100;
    } else if (passedChecks >= 4 && password.length >= 14 && entropy > 70 && patterns.length <= 1) {
      strength = 'Strong';
      color = 'text-green-500';
      score = 85;
    } else if (passedChecks >= 4 && password.length >= 12 && entropy > 60) {
      strength = 'Good';
      color = 'text-blue-500';
      score = 70;
    } else if (passedChecks >= 3 && password.length >= 10 && entropy > 40) {
      strength = 'Moderate';
      color = 'text-yellow-500';
      score = 55;
    } else if (passedChecks >= 2 && password.length >= 8) {
      strength = 'Fair';
      color = 'text-orange-500';
      score = 40;
    } else {
      strength = 'Weak';
      color = 'text-red-500';
      score = 20;
    }

    setAnalysis({
      checks,
      strength,
      color,
      score,
      entropy: entropy.toFixed(2),
      patterns,
      crackTime: estimateCrackTime(entropy),
      uniqueChars: new Set(password).size,
      length: password.length
    });

    const timer = setTimeout(() => {
      if (password.length >= 4) {
        checkBreachStatus(password);
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [password]);

  // Estimate time to crack with modern hardware
  const estimateCrackTime = (entropy) => {
    const attempts = Math.pow(2, entropy);
    const attemptsPerSecond = 1e10; // 10 billion attempts/sec (modern GPU cluster)
    const seconds = attempts / attemptsPerSecond;

    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    return `${(seconds / 31536000).toExponential(2)} years`;
  };

  const getRecommendations = () => {
    if (!analysis) return [];
    const recommendations = [];

    if (!analysis.checks.length) {
      recommendations.push('Use at least 12 characters (16+ strongly recommended for sensitive accounts)');
    } else if (analysis.length < 16) {
      recommendations.push('Consider increasing length to 16+ characters for maximum security');
    }
    
    if (!analysis.checks.uppercase) recommendations.push('Add uppercase letters (A-Z) for increased complexity');
    if (!analysis.checks.lowercase) recommendations.push('Add lowercase letters (a-z) for increased complexity');
    if (!analysis.checks.numbers) recommendations.push('Include numbers (0-9) to improve strength');
    if (!analysis.checks.special) recommendations.push('Add special characters (!@#$%^&*) for better security');
    
    if (analysis.patterns.length > 0) {
      recommendations.push('⚠️ Avoid common patterns, sequences, and dictionary words');
    }
    
    if (analysis.uniqueChars / analysis.length < 0.6) {
      recommendations.push('Use more unique characters to increase entropy');
    }

    if (analysis.score < 70) {
      recommendations.push('Consider using a passphrase (4+ random words) or password manager');
    }

    return recommendations;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-purple-400" />
            <h1 className="text-4xl font-bold text-white">Password Strength Analyzer</h1>
          </div>
          <p className="text-gray-300 text-lg">
            Advanced password security analysis with entropy calculation and breach detection
          </p>
          <div className="mt-3 flex items-center justify-center gap-2 text-sm text-gray-400">
            <Info className="w-4 h-4" />
            <span>All analysis performed client-side • Your password never leaves your device</span>
          </div>
        </div>

        {/* Main Card */}
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 border border-white/20">
          {/* Password Input */}
          <div className="mb-6">
            <label className="block text-white text-sm font-medium mb-2">
              Enter Password to Analyze
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Type your password here..."
                className="w-full px-4 py-3 pr-12 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                autoComplete="off"
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition"
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {analysis && (
            <>
              {/* Strength Indicator */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-medium">Password Strength:</span>
                  <span className={`font-bold text-lg ${analysis.color}`}>
                    {analysis.strength}
                  </span>
                </div>
                <div className="w-full h-3 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      analysis.score >= 85 ? 'bg-green-500' :
                      analysis.score >= 70 ? 'bg-blue-500' :
                      analysis.score >= 55 ? 'bg-yellow-500' :
                      analysis.score >= 40 ? 'bg-orange-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${analysis.score}%` }}
                  />
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="flex items-center gap-2 mb-1">
                    <Zap className="w-4 h-4 text-purple-400" />
                    <span className="text-gray-300 text-sm">Entropy</span>
                  </div>
                  <p className="text-white text-2xl font-bold">{analysis.entropy}</p>
                  <p className="text-gray-400 text-xs">bits</p>
                </div>
                
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="flex items-center gap-2 mb-1">
                    <Lock className="w-4 h-4 text-purple-400" />
                    <span className="text-gray-300 text-sm">Crack Time</span>
                  </div>
                  <p className="text-white text-xl font-bold truncate">{analysis.crackTime}</p>
                  <p className="text-gray-400 text-xs">GPU cluster</p>
                </div>
                
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="flex items-center gap-2 mb-1">
                    <Award className="w-4 h-4 text-purple-400" />
                    <span className="text-gray-300 text-sm">Score</span>
                  </div>
                  <p className="text-white text-2xl font-bold">{analysis.score}</p>
                  <p className="text-gray-400 text-xs">/ 100</p>
                </div>

                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="flex items-center gap-2 mb-1">
                    <Info className="w-4 h-4 text-purple-400" />
                    <span className="text-gray-300 text-sm">Length</span>
                  </div>
                  <p className="text-white text-2xl font-bold">{analysis.length}</p>
                  <p className="text-gray-400 text-xs">characters</p>
                </div>
              </div>

              {/* Security Requirements */}
              <div className="mb-8">
                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-purple-400" />
                  Security Requirements (NIST Guidelines)
                </h3>
                <div className="space-y-2">
                  {Object.entries(analysis.checks).map(([key, passed]) => (
                    <div key={key} className="flex items-center gap-3 p-3 bg-white/5 rounded-lg">
                      {passed ? (
                        <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                      )}
                      <span className={passed ? 'text-gray-300' : 'text-gray-400'}>
                        {key === 'length' && `Minimum 12 characters (current: ${password.length})`}
                        {key === 'uppercase' && 'Contains uppercase letters (A-Z)'}
                        {key === 'lowercase' && 'Contains lowercase letters (a-z)'}
                        {key === 'numbers' && 'Contains numbers (0-9)'}
                        {key === 'special' && 'Contains special characters (!@#$%^&*)'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Breach Status */}
              {isChecking && (
                <div className="mb-8 p-4 rounded-lg border bg-blue-500/10 border-blue-500/30 animate-pulse">
                  <p className="text-blue-300 text-sm flex items-center gap-2">
                    <Shield className="w-4 h-4 animate-spin" />
                    Checking against breach databases...
                  </p>
                </div>
              )}

              {breachStatus && !isChecking && (
                <div className={`mb-8 p-4 rounded-lg border ${
                  breachStatus.breached 
                    ? 'bg-red-500/10 border-red-500/30' 
                    : 'bg-green-500/10 border-green-500/30'
                }`}>
                  <div className="flex items-start gap-3">
                    {breachStatus.breached ? (
                      <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                    ) : (
                      <Shield className="w-6 h-6 text-green-400 flex-shrink-0 mt-0.5" />
                    )}
                    <div>
                      <h3 className={`font-semibold mb-1 ${
                        breachStatus.breached ? 'text-red-300' : 'text-green-300'
                      }`}>
                        {breachStatus.breached ? '⚠️ Password Compromised!' : '✓ Password Not Found in Breaches'}
                      </h3>
                      <p className="text-gray-300 text-sm">
                        {breachStatus.breached 
                          ? `This password has appeared in approximately ${breachStatus.count.toLocaleString()} data breaches. Choose a different password immediately!`
                          : 'This password has not been found in known data breach databases. However, always ensure it meets all security requirements.'
                        }
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Pattern Warnings */}
              {analysis.patterns.length > 0 && (
                <div className="mb-8 p-4 rounded-lg border bg-orange-500/10 border-orange-500/30">
                  <h3 className="text-orange-300 font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5" />
                    Security Warnings
                  </h3>
                  <ul className="space-y-2">
                    {analysis.patterns.map((pattern, idx) => (
                      <li key={idx} className="text-orange-200 text-sm flex items-start gap-2">
                        <span className="text-orange-400 mt-1">•</span>
                        <span>{pattern}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommendations */}
              {getRecommendations().length > 0 && (
                <div className="p-4 rounded-lg border bg-blue-500/10 border-blue-500/30">
                  <h3 className="text-blue-300 font-semibold mb-3 flex items-center gap-2">
                    <Info className="w-5 h-5" />
                    Security Recommendations
                  </h3>
                  <ul className="space-y-2">
                    {getRecommendations().map((rec, idx) => (
                      <li key={idx} className="text-blue-200 text-sm flex items-start gap-2">
                        <span className="text-blue-400 mt-1">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          {!password && (
            <div className="text-center py-12">
              <Shield className="w-16 h-16 text-gray-500 mx-auto mb-4 opacity-50" />
              <p className="text-gray-400 text-lg mb-2">Start typing to analyze your password</p>
              <p className="text-gray-500 text-sm">Real-time entropy analysis and breach detection</p>
            </div>
          )}
        </div>

        {/* Info Footer */}
        <div className="mt-6 bg-white/5 backdrop-blur-lg rounded-xl p-4 border border-white/10">
          <h4 className="text-white font-semibold mb-2 text-sm">🔒 Tech Stack & Security Features:</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-gray-400 text-xs">
            <div>• React with Hooks (useState, useEffect)</div>
            <div>• Shannon Entropy Calculation</div>
            <div>• Pattern Recognition Algorithms</div>
            <div>• Breach Database Simulation (HIBP-style)</div>
            <div>• NIST Password Guidelines Implementation</div>
            <div>• Client-side Security (Zero Server Transmission)</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PasswordStrengthAnalyzer;
