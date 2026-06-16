#!/bin/bash
# vett.sh — multi-scanner security gate for OpenClaw skills
# Usage: bash vett.sh <skill-name | github-url | local-path>

set -euo pipefail

# Ensure Go binaries are in PATH
export PATH="$HOME/go/bin:$PATH"

INPUT="${1:-}"
if [ -z "$INPUT" ]; then
    echo "Usage: bash vett.sh <skill-name | github-url | local-path>"
    exit 1
fi

TMPDIR_BASE=$(mktemp -d /tmp/skill-vetter-XXXXXX)
trap 'rm -rf "$TMPDIR_BASE"' EXIT

SKILL_DIR=""
SKILL_NAME=""

# ── Resolve input to a local directory ──────────────────────────────────────

if [ -d "$INPUT" ]; then
    SKILL_DIR="$INPUT"
    SKILL_NAME=$(basename "$INPUT")
elif echo "$INPUT" | grep -q "^https://github.com"; then
    SKILL_NAME=$(basename "$INPUT" .git)
    SKILL_DIR="$TMPDIR_BASE/$SKILL_NAME"
    echo "📥 Cloning $INPUT ..."
    git clone --depth 1 "$INPUT" "$SKILL_DIR" 2>/dev/null
else
    # Treat as a ClawHub skill name — download via clawhub to tmp
    SKILL_NAME="$INPUT"
    SKILL_DIR="$TMPDIR_BASE/$SKILL_NAME"
    echo "📥 Downloading $SKILL_NAME from ClawHub to temp directory..."
    # Use --workdir and --dir to install to temp location
    clawhub --workdir "$TMPDIR_BASE" --dir . install "$SKILL_NAME" --force 2>/dev/null \
        || { echo "❌ Could not download skill '$SKILL_NAME' from ClawHub"; exit 1; }
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "SKILL VETTER — Security Scan: $SKILL_NAME"
echo "Path: $SKILL_DIR"
echo "════════════════════════════════════════════════════════════"
echo ""

FAILURES=0
WARNINGS=0
REPORT=""

append() {
    REPORT="${REPORT}\n$1"
}

# ── Scanner 1: aguara (prompt injection detection) ──────────────────────────

scan_aguara() {
    echo "[1/4] aguara............."
    
    if ! command -v aguara &>/dev/null; then
        append "⚠️  aguara not installed — skipping"
        echo "                      ⚠️  SKIP — not installed"
        echo "                         https://github.com/garagon/aguara"
        return 0
    fi
    
    local result
    result=$(aguara scan "$SKILL_DIR" --format json 2>/dev/null)
    
    # Check for high severity findings (severity >= 4)
    local high_count
    high_count=$(echo "$result" | jq '[.findings[] | select(.severity >= 4)] | length' 2>/dev/null || echo "0")
    
    local medium_count
    medium_count=$(echo "$result" | jq '[.findings[] | select(.severity >= 3 and .severity < 4)] | length' 2>/dev/null || echo "0")
    
    if [ "$high_count" -gt 0 ]; then
        append "❌ aguara: $high_count HIGH severity findings detected"
        echo "$result" | jq -r '.findings[] | select(.severity >= 4) | "   → \(.rule_id): \(.description) (\(.file_path):\(.line))"' 2>/dev/null
        echo "                      ❌ FAIL ($high_count high)"
        ((FAILURES++)) || true
    elif [ "$medium_count" -gt 0 ]; then
        append "⚠️  aguara: $medium_count MEDIUM severity findings (review manually)"
        echo "$result" | jq -r '.findings[] | select(.severity >= 3 and .severity < 4) | "   → \(.rule_id): \(.description) (\(.file_path):\(.line))"' 2>/dev/null
        echo "                      ⚠️  WARN ($medium_count medium)"
        ((WARNINGS++)) || true
    else
        append "✅ aguara: No prompt injection patterns found"
        echo "                      ✅ PASS"
    fi
}

# ── Scanner 2: skill-analyzer (Cisco vulnerability scanner) ────────────────

scan_skill_analyzer() {
    echo "[2/4] skill-analyzer....."
    
    if ! command -v skill-scanner &>/dev/null; then
        append "⚠️  skill-scanner not installed — skipping"
        echo "                      ⚠️  SKIP — not installed"
        echo "                         https://pypi.org/project/cisco-ai-skill-scanner/"
        return 0
    fi

    local result
    result=$(skill-scanner scan "$SKILL_DIR" --format json 2>/dev/null || echo '{}')

    # Aggregate by per-finding severity (top-level .severity is null in v2.x)
    local critical_count high_count medium_count
    critical_count=$(echo "$result" | jq '[.findings[]? | select((.severity // "" | ascii_upcase) == "CRITICAL")] | length' 2>/dev/null || echo "0")
    high_count=$(echo "$result" | jq '[.findings[]? | select((.severity // "" | ascii_upcase) == "HIGH")] | length' 2>/dev/null || echo "0")
    medium_count=$(echo "$result" | jq '[.findings[]? | select((.severity // "" | ascii_upcase) == "MEDIUM")] | length' 2>/dev/null || echo "0")

    if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
        local sev_label="HIGH"
        [ "$critical_count" -gt 0 ] && sev_label="CRITICAL"
        append "❌ skill-scanner: $critical_count CRITICAL, $high_count HIGH findings"
        echo "$result" | jq -r '.findings[]? | select((.severity // "" | ascii_upcase) == "CRITICAL" or (.severity // "" | ascii_upcase) == "HIGH") | "   → \(.rule_id // .title): \(.description // "" | gsub("\n"; " ")) (\(.file_path // "?"):\(.line_number // .line // "?"))"' 2>/dev/null
        echo "                      ❌ FAIL ($sev_label)"
        ((FAILURES++)) || true
    elif [ "$medium_count" -gt 0 ]; then
        append "⚠️  skill-scanner: $medium_count MEDIUM severity findings"
        echo "$result" | jq -r '.findings[]? | select((.severity // "" | ascii_upcase) == "MEDIUM") | "   → \(.rule_id // .title): \(.description // "" | gsub("\n"; " ")) (\(.file_path // "?"):\(.line_number // .line // "?"))"' 2>/dev/null
        echo "                      ⚠️  WARN (medium)"
        ((WARNINGS++)) || true
    else
        append "✅ skill-scanner: No critical vulnerabilities found"
        echo "                      ✅ PASS"
    fi
}

# ── Scanner 3: secrets-scan (hardcoded credentials) ─────────────────────────

scan_secrets() {
    echo "[3/4] secrets-scan......."
    
    local found_secrets=0
    
    # Check for common secret patterns (case-insensitive — keys often UPPER_CASE)
    if grep -rqEi "(api[_-]?key|secret|token|password|credential|bearer)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]" "$SKILL_DIR" 2>/dev/null; then
        found_secrets=1
    fi

    # Check for base64 encoded strings that might be secrets
    local found_base64=0
    if grep -rqE "['\"][A-Za-z0-9+/]{40,}={0,2}['\"]" "$SKILL_DIR" --include="*.sh" --include="*.py" --include="*.js" 2>/dev/null; then
        found_base64=1
    fi

    if [ $found_secrets -eq 1 ]; then
        append "❌ secrets-scan: Hardcoded credentials detected"
        echo "                      ❌ FAIL (credentials found)"
        ((FAILURES++)) || true
    elif [ $found_base64 -eq 1 ]; then
        append "⚠️  secrets-scan: Found base64 encoded strings (review manually)"
        echo "                      ⚠️  WARN (base64 strings)"
        ((WARNINGS++)) || true
    else
        append "✅ secrets-scan: No hardcoded secrets found"
        echo "                      ✅ PASS"
    fi
}

# ── Scanner 4: structure-check (required files, dangerous patterns) ─────────

scan_structure() {
    echo "[4/4] structure-check...."
    
    local issues=0
    
    # Check for SKILL.md
    if [ ! -f "$SKILL_DIR/SKILL.md" ]; then
        append "❌ structure-check: Missing SKILL.md"
        ((issues++)) || true
    fi
    
    # Check for README.md (SKILL.md should be the primary doc)
    if [ -f "$SKILL_DIR/README.md" ]; then
        append "ℹ️  structure-check: README.md exists (SKILL.md is the primary doc for agents)"
    fi
    
    # Check for dangerous commands in scripts and code
    if grep -rqE "(rm -rf|curl.*\|.*bash|wget.*\|.*sh|eval\s|exec\s)" "$SKILL_DIR" --include="*.sh" --include="*.py" --include="*.js" --exclude="vett.sh" 2>/dev/null; then
        append "❌ structure-check: Dangerous shell commands detected"
        ((issues++)) || true
    fi
    
    # Check YAML frontmatter in SKILL.md
    if [ -f "$SKILL_DIR/SKILL.md" ]; then
        if ! head -5 "$SKILL_DIR/SKILL.md" | grep -q "^---"; then
            append "⚠️  structure-check: SKILL.md missing YAML frontmatter"
            ((WARNINGS++)) || true
        fi
    fi
    
    if [ $issues -gt 0 ]; then
        echo "                      ❌ FAIL ($issues issues)"
        ((FAILURES++)) || true
    else
        append "✅ structure-check: Skill structure valid"
        echo "                      ✅ PASS"
    fi
}

# ── Run all scanners ────────────────────────────────────────────────────────

scan_aguara
scan_skill_analyzer
scan_secrets
scan_structure

# ── Generate verdict ────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"

if [ $FAILURES -gt 0 ]; then
    echo "VERDICT: 🚫 BLOCKED"
    echo "Reasons: $FAILURES HIGH/CRITICAL, $WARNINGS MEDIUM"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "Do NOT install this skill. Issues found:"
    echo -e "$REPORT"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo "VERDICT: ⚠️  REVIEW NEEDED"
    echo "Reasons: $WARNINGS MEDIUM severity findings"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "Review these findings before installing:"
    echo -e "$REPORT"
    exit 0
else
    echo "VERDICT: ✅ SAFE"
    echo "All scanners passed"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo -e "$REPORT"
    exit 0
fi
