# [PASSSEC] — Password Security Analyzer

> A professional, client-side password security tool with entropy analysis, pattern detection, brute-force estimation, and secure password generation. Built for GitHub Pages — no backend required.

![Preview](https://img.shields.io/badge/Live_Demo-GitHub_Pages-00e5a0?style=for-the-badge)
![Language](https://img.shields.io/badge/HTML%2FCSS%2FJS-100%25_Client_Side-0090ff?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-white?style=for-the-badge)

---

## Features

| Feature | Description |
|---|---|
| **Entropy Analysis** | Calculates Shannon entropy using charset size × length |
| **Pattern Detection** | Detects sequences, keyboard walks, common substitutions |
| **Brute-Force Estimator** | Time-to-crack at 10⁹ guesses/sec (modern GPU) |
| **Dictionary Check** | Flags passwords found in common password lists |
| **Security Checklist** | Visual checklist of 8 best-practice requirements |
| **Entropy Visualization** | Canvas bar chart + entropy scale needle |
| **Password Generator** | Cryptographically secure (Web Crypto API) with controls |
| **100% Client-Side** | No data ever leaves your browser |

---

## Live Demo

**→ [Open on GitHub Pages](https://eliamcodes.github.io/password-security-analyzer)**

---

## Concepts Demonstrated

### 1. Shannon Entropy
```
E = L × log₂(N)
```
Where:
- `L` = password length  
- `N` = number of possible characters in charset

Higher entropy = harder to crack by brute force.

### 2. Brute-Force Attack Simulation
```
Combinations = N ^ L
Crack time = Combinations / (guesses_per_second)
```
Assumes 1,000,000,000 guesses/second (modern GPU hashcat benchmark).

### 3. Pattern Categories Detected
- Sequential numbers: `123`, `456`
- Alphabetical sequences: `abc`, `def`
- Keyboard walks: `qwerty`, `asdf`, `zxcv`
- Repeated characters: `aaa`, `111`
- Common password dictionary match

### 4. Password Strength Scale
| Entropy | Strength |
|---|---|
| 0–28 bits | Very Weak |
| 28–40 bits | Weak |
| 40–56 bits | Fair |
| 56–80 bits | Strong |
| 80+ bits | Very Strong |
| 128+ bits | Uncrackable |

---

## File Structure

```
password-security-analyzer/
├── index.html       # Main UI (semantic HTML5)
├── style.css        # Custom design system (CSS variables + animations)
├── app.js           # All logic (entropy, patterns, generator, charts)
└── README.md        # This file
```

---

## How to Run Locally

```bash
git clone https://github.com/eliamcodes/password-security-analyzer.git
cd password-security-analyzer
# Open index.html in any modern browser — no server required
open index.html
```

Or serve it locally:
```bash
npx serve .
# or
python -m http.server 8080
```

---

## Deploy to GitHub Pages

1. Push to GitHub
2. Go to **Settings → Pages**
3. Set source: `main` branch, `/ (root)`
4. Your site will be live at `https://yourusername.github.io/password-security-analyzer`

---

## Tech Stack

- **HTML5** — Semantic markup, accessible
- **CSS3** — Custom properties, Grid, Flexbox, animations
- **Vanilla JavaScript** — No frameworks, no dependencies
- **Web Crypto API** — Cryptographically secure random generation
- **Canvas API** — Custom bar chart visualization

---

## Security Note

This tool is for **educational purposes**. All analysis runs client-side in your browser. No passwords are stored, transmitted, or logged anywhere.

---

## Author

**Eliam** — Cybersecurity & Software Development Student  
Built as a portfolio project demonstrating: entropy math, pattern analysis, CLI architecture, API design, and modern frontend development.

---

## License

MIT — free to use, modify, and distribute.
