#!/usr/bin/env bash
# =============================================================================
# Agentic Email Security System – System Cleanup
# =============================================================================
# Cleans up temporary files, pycache, and rotates old analysis reports.
# - Keeps ALL training-related reports and images.
# - Keeps only the latest run for each other report type.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EMAIL_SEC_DIR="$PROJECT_ROOT/email_security"

echo "============================================="
echo " Agentic Email Security – System Cleanup"
echo "============================================="

# 1. Cleanup Python Bytecode
echo "[*] Cleaning up Python cache files..."
find "$PROJECT_ROOT" -name "__pycache__" -type d -exec rm -rf {} +
find "$PROJECT_ROOT" -name "*.pyc" -delete
echo "    Done."

# 2. Cleanup Analysis Reports
REPORTS_DIR="$EMAIL_SEC_DIR/analysis_reports"
if [ -d "$REPORTS_DIR" ]; then
    echo "[*] Cleaning up old analysis reports in $REPORTS_DIR..."
    cd "$REPORTS_DIR"
    
    # Find all items that match the timestamp pattern _YYYYMMDD_HHMMSS
    # and do NOT contain "train" (protected)
    items_with_ts=$(ls -1 | grep -E '_[0-9]{8}_[0-9]{6}' | grep -v "train" || true)
    
    if [ -n "$items_with_ts" ]; then
        # Extract unique prefixes
        prefixes=$(echo "$items_with_ts" | sed -E 's/_[0-9]{8}_[0-9]{6}.*//' | sort -u)
        
        for p in $prefixes; do
            echo "  → Rotating group: $p"
            
            # Get all items for this exact prefix followed by a timestamp
            # Sort them in reverse order (latest date/time first)
            all_for_prefix=$(ls -1d ${p}_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]* 2>/dev/null | sort -r || true)
            
            if [ -n "$all_for_prefix" ]; then
                # The first one is the latest
                latest=$(echo "$all_for_prefix" | head -n 1)
                
                # Others are candidates for deletion
                to_delete=$(echo "$all_for_prefix" | tail -n +2)
                
                if [ -n "$to_delete" ]; then
                    while read -r item; do
                        if [ -n "$item" ]; then
                            echo "    [-] Deleting old report: $item"
                            rm -rf "$item"
                        fi
                    done <<< "$to_delete"
                else
                    echo "    [+] Only one report found, keeping: $latest"
                fi
            fi
        done
    else
        echo "    No report groups found for rotation."
    fi
else
    echo "[!] Analysis reports directory not found at $REPORTS_DIR. Skipping."
fi

echo ""
echo "Cleanup complete."
