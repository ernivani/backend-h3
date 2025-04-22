#!/bin/bash

# This script triggers the breach detection mechanism and sends alerts if needed
# It should be run as a cron job, e.g., once per day: 
# 0 2 * * * /path/to/breach_scan.sh

# Configuration
API_URL="http://localhost:8000/api/security/scan"
ADMIN_TOKEN="your_admin_token_here"  # In production, use a secure way to store this
LOG_FILE="/var/log/breach_scan.log"

# Create log directory if it doesn't exist
mkdir -p $(dirname $LOG_FILE)

# Log start
echo "$(date): Starting GDPR breach scan" >> $LOG_FILE

# Run the scan
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  $API_URL)

# Check if successful
if echo "$RESPONSE" | grep -q "success"; then
  NUM_INCIDENTS=$(echo "$RESPONSE" | grep -o 'Found [0-9]* potential incidents' | grep -o '[0-9]*')
  echo "$(date): Scan completed successfully. Found $NUM_INCIDENTS potential incidents." >> $LOG_FILE
  
  # If high-severity incidents were found, the API would have created notification files
  # You can add additional alerting here if needed, e.g., email notifications
  if [ "$NUM_INCIDENTS" -gt 0 ]; then
    echo "$(date): Potential security incidents detected. Check notification files." >> $LOG_FILE
    
    # In a real implementation, you might want to email security team here
    # mail -s "GDPR Security Alert: Potential Data Breach" security@example.com < $LOG_FILE
  fi
else
  echo "$(date): Scan failed. Response: $RESPONSE" >> $LOG_FILE
  # Notify admin of failure
  # mail -s "GDPR Breach Scan Failed" admin@example.com < $LOG_FILE
fi

echo "$(date): Breach scan complete" >> $LOG_FILE
exit 0 