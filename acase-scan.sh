#!/bin/bash

TARGET=$1
EMAIL=$2
REPORT_DIR="$HOME/acase/reports"

if [ -z "$TARGET" ] || [ -z "$EMAIL" ]; then
  echo "Usage: ./acase-scan.sh <target> <email>"
  exit 1
fi

echo "[*] Starting ACASE scan..."
python3 acase.py "$TARGET" --test-email "$EMAIL"

LATEST_REPORT=$(ls -t $REPORT_DIR/acase_report_*.txt | head -n 1)

echo ""
echo "[*] Performing HTTP status analysis..."

VALID=$(curl -s -o /tmp/valid.out -w "%{http_code}" -X POST "$TARGET/reset.php" -d "email=$EMAIL")
INVALID=$(curl -s -o /tmp/invalid.out -w "%{http_code}" -X POST "$TARGET/reset.php" -d "email=fake_123@test.com")

VALID_LEN=$(wc -c < /tmp/valid.out)
INVALID_LEN=$(wc -c < /tmp/invalid.out)

{
echo ""
echo "[STATUS CODE ANALYSIS]"
echo "Valid Email   -> Status: $VALID | Length: $VALID_LEN"
echo "Invalid Email -> Status: $INVALID | Length: $INVALID_LEN"

if [ "$VALID" != "$INVALID" ] || [ "$VALID_LEN" != "$INVALID_LEN" ]; then
   echo "[!] Enumeration confirmed via response difference."
else
   echo "[+] No enumeration detected."
fi
} >> "$LATEST_REPORT"

echo "[+] Status code results added to report."

echo "[*] Opening email inbox..."
firefox http://127.0.0.1:8025 &>/dev/null &

echo "[+] Scan complete. Report ready."
