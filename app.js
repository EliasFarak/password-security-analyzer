// =============================================
// PassSec — Password Security Analyzer
// Author: Eliam | Educational Cybersecurity Tool
// =============================================

'use strict';

// ===== COMMON PASSWORDS (Top 200 most used) =====
const COMMON_PASSWORDS = new Set([
  '123456','password','123456789','12345678','12345','1234567','1234567890',
  'qwerty','abc123','million2','000000','1234','iloveyou','aaron431','password1',
  'qqww1122','123123','omgpop','123321','654321','qwertyuiop','qwerty123',
  '1q2w3e4r','admin','letmein','welcome','monkey','login','princess',
  'solo','passw0rd','starwars','dragon','master','hello','freedom','whatever',
  'shadow','superman','michael','football','jesus','ninja','mustang','password2',
  'shadow','master','666666','987654321','12345678','password','123456',
  'hola123','admin123','root','toor','pass','test','guest','default',
  'changeme','abc','abcd','qwerty1','password123','1password','pass1','pass123',
  'p@ssword','p@ss','passw0rd1','pa$$w0rd','pa$$word','hunter2','trustno1',
  'sunshine','princess','welcome1','shadow1','baseball','iloveyou1','batman',
  'superman1','spiderman','pokemon','naruto','access','hello1','lovely',
  'apple','orange','google','facebook','twitter','instagram','linkedin',
]);

// ===== ENTROPY CALCULATOR =====
function getCharsetSize(password) {
  let size = 0;
  const types = [];
  if (/[a-z]/.test(password)) { size += 26; types.push('a–z'); }
  if (/[A-Z]/.test(password)) { size += 26; types.push('A–Z'); }
  if (/[0-9]/.test(password)) { size += 10; types.push('0–9'); }
  if (/[^a-zA-Z0-9]/.test(password)) { size += 32; types.push('symbols'); }
  return { size, types };
}

function calculateEntropy(password) {
  const { size } = getCharsetSize(password);
  if (size === 0 || password.length === 0) return 0;
  return password.length * Math.log2(size);
}

// ===== PATTERN DETECTOR =====
function detectPatterns(password) {
  const issues = [];
  const p = password.toLowerCase();

  if (/(.)\1{2,}/.test(password)) issues.push('Repeated characters (e.g. aaa, 111)');
  if (/012|123|234|345|456|567|678|789|890/.test(p)) issues.push('Sequential numeric pattern');
  if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm/.test(p)) issues.push('Sequential alphabetical pattern');
  if (/qwert|asdf|zxcv|qazwsx|qweasd/.test(p)) issues.push('Keyboard walk pattern');
  if (/^[a-z]+$/.test(password)) issues.push('All lowercase — no uppercase');
  if (/^[A-Z]+$/.test(password)) issues.push('All uppercase — no lowercase');
  if (/^\d+$/.test(password)) issues.push('Numbers only');
  if (/^[a-zA-Z]+$/.test(password)) issues.push('Letters only — no numbers/symbols');
  if (password.length < 8) issues.push('Too short (minimum 8 characters)');
  if (COMMON_PASSWORDS.has(p)) issues.push('⚠ Found in common passwords list!');

  return issues;
}

// ===== BRUTE FORCE ESTIMATOR =====
function estimateCrackTime(password) {
  const { size } = getCharsetSize(password);
  if (size === 0) return 0;
  const combinations = Math.pow(size, password.length);
  const guessesPerSecond = 1e9;
  return combinations / guessesPerSecond;
}

function formatTime(seconds) {
  if (seconds < 0.001) return '< 1ms';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(1)} min`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(1)} hours`;
  const days = hours / 24;
  if (days < 30) return `${days.toFixed(1)} days`;
  const months = days / 30;
  if (months < 12) return `${months.toFixed(1)} months`;
  const years = days / 365;
  if (years < 1e6) return `${formatLargeNum(years)} years`;
  if (years < 1e12) return `${(years / 1e6).toFixed(1)}M years`;
  if (years < 1e18) return `${(years / 1e12).toFixed(1)}T years`;
  return 'Heat death of universe+';
}

function formatLargeNum(n) {
  if (n >= 1e9) return `${(n/1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n/1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n/1e3).toFixed(1)}K`;
  return n.toFixed(0);
}

function formatCombinations(password) {
  const { size } = getCharsetSize(password);
  const exp = password.length * Math.log10(size);
  if (exp < 15) {
    const n = Math.pow(size, password.length);
    return formatLargeNum(n);
  }
  return `10^${exp.toFixed(0)}`;
}

// ===== STRENGTH SCORE =====
function getStrength(entropy) {
  if (entropy < 28) return { label: 'Very Weak', color: '#ff3b5c', pct: 10 };
  if (entropy < 40) return { label: 'Weak', color: '#ff6b35', pct: 28 };
  if (entropy < 56) return { label: 'Fair', color: '#ffb547', pct: 52 };
  if (entropy < 80) return { label: 'Strong', color: '#00e5a0', pct: 74 };
  if (entropy < 128) return { label: 'Very Strong', color: '#0090ff', pct: 90 };
  return { label: 'Uncrackable', color: '#a78bfa', pct: 100 };
}

// ===== PASSWORD GENERATOR =====
function generatePassword(length = 16, opts = { lower: true, upper: true, digits: true, symbols: true }) {
  const sets = [];
  if (opts.lower) sets.push('abcdefghijklmnopqrstuvwxyz');
  if (opts.upper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (opts.digits) sets.push('0123456789');
  if (opts.symbols) sets.push('!@#$%^&*()-_=+[]{}|;:,.<>?');

  if (sets.length === 0) return '';

  const all = sets.join('');
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  // Ensure at least one char from each set
  const chars = [];
  sets.forEach(set => {
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % set.length;
    chars.push(set[idx]);
  });

  // Fill the rest
  for (let i = chars.length; i < length; i++) {
    chars.push(all[array[i] % all.length]);
  }

  // Shuffle using Fisher-Yates
  const shuffleArr = new Uint32Array(chars.length);
  crypto.getRandomValues(shuffleArr);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = shuffleArr[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

// ===== CANVAS CHART =====
function drawCharChart(password) {
  const canvas = document.getElementById('charChart');
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const categories = [
    { label: 'Lowercase', regex: /[a-z]/g, color: '#00e5a0' },
    { label: 'Uppercase', regex: /[A-Z]/g, color: '#0090ff' },
    { label: 'Digits', regex: /[0-9]/g, color: '#ffb547' },
    { label: 'Symbols', regex: /[^a-zA-Z0-9]/g, color: '#ff6b35' },
  ];

  const counts = categories.map(c => {
    const m = password.match(c.regex);
    return { ...c, count: m ? m.length : 0 };
  });

  const maxVal = Math.max(...counts.map(c => c.count), 1);
  const barW = 44;
  const barGap = (w - categories.length * barW) / (categories.length + 1);
  const chartH = h - 50;
  const bg = '#111820';

  // Background
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, w, h);

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  for (let i = 1; i <= 4; i++) {
    const y = chartH - (chartH * i / 4) + 10;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  counts.forEach((cat, i) => {
    const x = barGap + i * (barW + barGap);
    const barH = cat.count > 0 ? (cat.count / maxVal) * (chartH - 20) : 0;
    const y = chartH - barH + 10;

    // Bar
    const grad = ctx.createLinearGradient(x, y, x, chartH + 10);
    grad.addColorStop(0, cat.color);
    grad.addColorStop(1, cat.color + '44');
    ctx.fillStyle = cat.count > 0 ? grad : 'rgba(255,255,255,0.05)';
    const r = 6;
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + barW - r, y);
    ctx.arcTo(x + barW, y, x + barW, y + r, r);
    ctx.lineTo(x + barW, chartH + 10);
    ctx.lineTo(x, chartH + 10);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
    ctx.fill();

    // Count label
    ctx.fillStyle = cat.count > 0 ? cat.color : 'rgba(255,255,255,0.2)';
    ctx.font = 'bold 13px "Space Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(cat.count, x + barW / 2, y - 6);

    // Label
    ctx.fillStyle = 'rgba(255,255,255,0.35)';
    ctx.font = '10px "Space Mono", monospace';
    ctx.fillText(cat.label, x + barW / 2, h - 8);
  });
}

// ===== ENTROPY NEEDLE =====
function updateNeedle(entropy) {
  const needle = document.getElementById('scaleNeedle');
  // Scale: 0 bits → 0%, 128+ bits → 100%
  const maxEntropy = 128;
  const pct = Math.min((entropy / maxEntropy) * 100, 100);
  needle.style.left = `${pct}%`;
}

// ===== CHECKLIST BUILDER =====
function buildChecklist(password) {
  const checks = [
    { label: '8+ characters', pass: password.length >= 8 },
    { label: '12+ characters', pass: password.length >= 12 },
    { label: 'Uppercase letters', pass: /[A-Z]/.test(password) },
    { label: 'Lowercase letters', pass: /[a-z]/.test(password) },
    { label: 'Numbers', pass: /[0-9]/.test(password) },
    { label: 'Special symbols', pass: /[^a-zA-Z0-9]/.test(password) },
    { label: 'No sequences', pass: !/012|123|234|345|abc|bcd/.test(password.toLowerCase()) },
    { label: 'Not a common password', pass: !COMMON_PASSWORDS.has(password.toLowerCase()) },
  ];
  return checks;
}

// ===== MAIN ANALYZE FUNCTION =====
function analyzePassword(password) {
  if (!password || password.length === 0) return;

  const entropy = calculateEntropy(password);
  const { size: charsetSize, types } = getCharsetSize(password);
  const patterns = detectPatterns(password);
  const crackSeconds = estimateCrackTime(password);
  const strength = getStrength(entropy);

  // Show containers
  document.getElementById('strengthContainer').style.display = 'block';
  document.getElementById('resultsGrid').style.display = 'grid';
  document.getElementById('checklist').style.display = 'block';
  document.getElementById('visualization').style.display = 'block';

  // Strength meter
  const fill = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');
  fill.style.width = strength.pct + '%';
  fill.style.background = strength.color;
  label.textContent = strength.label;
  label.style.color = strength.color;

  // Cards
  document.getElementById('entropyValue').textContent = entropy.toFixed(1);
  const entropyBar = document.getElementById('entropyBar');
  entropyBar.style.width = Math.min((entropy / 128) * 100, 100) + '%';

  document.getElementById('crackValue').textContent = formatTime(crackSeconds);
  document.getElementById('charsetValue').textContent = charsetSize;
  document.getElementById('charsetTypes').textContent = types.join(', ') || 'none';
  document.getElementById('comboValue').textContent = formatCombinations(password);

  // Color crack time by severity
  const crackEl = document.getElementById('crackValue');
  if (crackSeconds < 60) crackEl.style.color = '#ff3b5c';
  else if (crackSeconds < 3600) crackEl.style.color = '#ff6b35';
  else if (crackSeconds < 86400) crackEl.style.color = '#ffb547';
  else crackEl.style.color = '#00e5a0';

  // Warnings
  const warnSection = document.getElementById('warningsSection');
  const successSection = document.getElementById('successSection');
  const warnList = document.getElementById('warningsList');

  if (patterns.length > 0) {
    warnList.innerHTML = patterns.map(p =>
      `<div class="warning-item">${p}</div>`
    ).join('');
    warnSection.style.display = 'block';
    successSection.style.display = 'none';
  } else {
    warnSection.style.display = 'none';
    successSection.style.display = 'flex';
  }

  // Checklist
  const checks = buildChecklist(password);
  const checklistEl = document.getElementById('checklistItems');
  checklistEl.innerHTML = checks.map(c => `
    <div class="check-item ${c.pass ? 'pass' : 'fail'}">
      <div class="check-dot ${c.pass ? 'pass' : 'fail'}"></div>
      ${c.label}
    </div>
  `).join('');

  // Visualization
  drawCharChart(password);
  updateNeedle(entropy);

  // Scroll to results on mobile
  if (window.innerWidth < 768) {
    document.getElementById('strengthContainer').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ===== EVENT LISTENERS =====
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('passwordInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const toggleBtn = document.getElementById('toggleBtn');

  // Real-time analysis
  input.addEventListener('input', () => {
    const val = input.value;
    if (val.length === 0) {
      document.getElementById('strengthContainer').style.display = 'none';
      document.getElementById('resultsGrid').style.display = 'none';
      document.getElementById('warningsSection').style.display = 'none';
      document.getElementById('successSection').style.display = 'none';
      document.getElementById('checklist').style.display = 'none';
      document.getElementById('visualization').style.display = 'none';
      return;
    }
    if (val.length >= 1) analyzePassword(val);
  });

  // Analyze button
  analyzeBtn.addEventListener('click', () => {
    const val = input.value;
    if (val) analyzePassword(val);
  });

  // Enter key
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && input.value) analyzePassword(input.value);
  });

  // Toggle visibility
  toggleBtn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggleBtn.innerHTML = isPassword
      ? `<svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
      : `<svg class="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  });

  // ===== GENERATOR =====
  const lengthSlider = document.getElementById('lengthSlider');
  const lengthDisplay = document.getElementById('lengthDisplay');
  const generateBtn = document.getElementById('generateBtn');
  const genOutput = document.getElementById('genOutput');
  const copyBtn = document.getElementById('copyBtn');
  const genStats = document.getElementById('genStats');

  lengthSlider.addEventListener('input', () => {
    lengthDisplay.textContent = lengthSlider.value;
    // Update slider gradient
    const pct = ((lengthSlider.value - lengthSlider.min) / (lengthSlider.max - lengthSlider.min)) * 100;
    lengthSlider.style.background = `linear-gradient(to right, #00e5a0 0%, #00e5a0 ${pct}%, #111820 ${pct}%)`;
  });

  function doGenerate() {
    const opts = {
      lower: document.getElementById('chkLower').checked,
      upper: document.getElementById('chkUpper').checked,
      digits: document.getElementById('chkDigits').checked,
      symbols: document.getElementById('chkSymbols').checked,
    };

    if (!opts.lower && !opts.upper && !opts.digits && !opts.symbols) {
      genOutput.textContent = 'Select at least one character type';
      return;
    }

    const length = parseInt(lengthSlider.value);
    const pwd = generatePassword(length, opts);
    genOutput.textContent = pwd;

    // Show stats
    const entropy = calculateEntropy(pwd);
    const crackSec = estimateCrackTime(pwd);
    const strength = getStrength(entropy);
    document.getElementById('genEntropy').textContent = entropy.toFixed(0);
    document.getElementById('genCrack').textContent = formatTime(crackSec);
    document.getElementById('genStrength').textContent = strength.label;
    document.getElementById('genStrength').style.color = strength.color;
    genStats.style.display = 'flex';
  }

  generateBtn.addEventListener('click', doGenerate);

  copyBtn.addEventListener('click', () => {
    const text = genOutput.textContent;
    if (!text || text.includes('Click') || text.includes('Select')) return;

    navigator.clipboard.writeText(text).then(() => {
      copyBtn.classList.add('copied');
      copyBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
      setTimeout(() => {
        copyBtn.classList.remove('copied');
        copyBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
      }, 2000);
    });
  });

  // Generate one on load
  doGenerate();
});
