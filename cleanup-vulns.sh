#!/bin/bash

# CRS Vulnerability Cleanup Script
# Usage: ./cleanup_vulns.sh [vuln_source] [vuln_id]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/data/products.sqlite3"

# Function to show help
show_help() {
    echo "CRS Vulnerability Cleanup Script"
    echo ""
    echo "Usage:"
    echo "  $0                          # Show all vulnerabilities"
    echo "  $0 <source>                 # Delete all vulnerabilities with source (e.g., 'diff_analyzer')"
    echo "  $0 <source> <vuln_id>       # Delete specific vulnerability ID"
    echo "  $0 --list                   # List all sources"
    echo "  $0 --help                   # Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 diff_analyzer            # Delete all diff_analyzer vulnerabilities"
    echo "  $0 diff_analyzer 4          # Delete specific vuln_id=4 if source is diff_analyzer"
    echo ""
}

# Function to list all vulnerability sources
list_sources() {
    echo "=== All Vulnerability Sources ==="
    sqlite3 "$DB_PATH" "SELECT source, COUNT(*) as count FROM vulns GROUP BY source ORDER BY count DESC;" 2>/dev/null || echo "Database not found or accessible"
}

# Function to show all vulnerabilities
show_vulns() {
    echo "=== All Vulnerabilities ==="
    sqlite3 "$DB_PATH" "SELECT id, source, project_name, function, file FROM vulns ORDER BY id;" 2>/dev/null || echo "Database not found or accessible"
}

# Function to query and confirm deletion
confirm_delete() {
    local source="$1"
    local vuln_id="$2"
    
    echo "=== Vulnerabilities to be deleted ==="
    
    if [[ -n "$vuln_id" ]]; then
        # Delete specific vuln_id
        sqlite3 "$DB_PATH" "SELECT id, source, project_name, function, file FROM vulns WHERE id = $vuln_id;" 2>/dev/null
        ROWS_AFFECTED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM vulns WHERE id = $vuln_id;" 2>/dev/null)
        
        if [[ "$ROWS_AFFECTED" -eq 0 ]]; then
            echo "No vulnerability found with ID = $vuln_id"
            exit 1
        fi
        
        echo ""
        echo "This will delete 1 vulnerability (ID: $vuln_id)"
        
    else
        # Delete all by source
        sqlite3 "$DB_PATH" "SELECT id, source, project_name, function, file FROM vulns WHERE source = '$source';" 2>/dev/null
        ROWS_AFFECTED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM vulns WHERE source = '$source';" 2>/dev/null)
        
        if [[ "$ROWS_AFFECTED" -eq 0 ]]; then
            echo "No vulnerabilities found with source = '$source'"
            exit 1
        fi
        
        echo ""
        echo "This will delete $ROWS_AFFECTED vulnerabilities with source = '$source'"
    fi
    
    echo ""
    read -p "Are you sure you want to proceed? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo "Deletion cancelled."
        exit 0
    fi
}

# Function to perform the deletion
delete_vulns() {
    local source="$1"
    local vuln_id="$2"
    
    echo "Deleting vulnerabilities..."
    
    # Check for related data first
    if [[ -n "$vuln_id" ]]; then
        # Check patches, povs, etc. for specific vuln_id
        PATCHES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM patches WHERE vuln_id = $vuln_id;" 2>/dev/null || echo "0")
        POVS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM povs WHERE vuln_id = $vuln_id;" 2>/dev/null || echo "0")
        
        if [[ "$PATCHES" -gt 0 || "$POVS" -gt 0 ]]; then
            echo "⚠️  Warning: Found related data:"
            echo "   - Patches: $PATCHES"
            echo "   - POVs: $POVS"
            echo ""
            read -p "This will also delete related data. Continue? (yes/no): " confirm
            if [[ "$confirm" != "yes" ]]; then
                exit 0
            fi
            
            # Clean up related data
            sqlite3 "$DB_PATH" "DELETE FROM patches WHERE vuln_id = $vuln_id;"
            sqlite3 "$DB_PATH" "DELETE FROM povs WHERE vuln_id = $vuln_id;"
        fi
        
        # Delete the vulnerability
        DELETED=$(sqlite3 "$DB_PATH" "DELETE FROM vulns WHERE id = $vuln_id; SELECT changes();")
        
    else
        # Delete by source
        # Get all vuln_ids to check for related data
        VULN_IDS=$(sqlite3 "$DB_PATH" "SELECT id FROM vulns WHERE source = '$source';" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        if [[ -n "$VULN_IDS" ]]; then
            # Check for related data
            PATCHES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM patches WHERE vuln_id IN ($VULN_IDS);" 2>/dev/null || echo "0")
            POVS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM povs WHERE vuln_id IN ($VULN_IDS);" 2>/dev/null || echo "0")
            
            if [[ "$PATCHES" -gt 0 || "$POVS" -gt 0 ]]; then
                echo "⚠️  Warning: Found related data:"
                echo "   - Patches: $PATCHES"
                echo "   - POVs: $POVS"
                echo ""
                read -p "This will also delete related data. Continue? (yes/no): " confirm
                if [[ "$confirm" != "yes" ]]; then
                    exit 0
                fi
                
                # Clean up related data
                sqlite3 "$DB_PATH" "DELETE FROM patches WHERE vuln_id IN ($VULN_IDS);"
                sqlite3 "$DB_PATH" "DELETE FROM povs WHERE vuln_id IN ($VULN_IDS);"
            fi
        fi        
        
        # Delete the vulnerabilities
        DELETED=$(sqlite3 "$DB_PATH" "DELETE FROM vulns WHERE source = '$source'; SELECT changes();")
    fi
    
    if [[ "$DELETED" -gt 0 ]]; then
        echo "✅ Successfully deleted $DELETED vulnerabilities"
    else
        echo "⚠️  No vulnerabilities were deleted"
    fi
}

# Check if database exists
if [[ ! -f "$DB_PATH" ]]; then
    echo "❌ Database not found: $DB_PATH"
    echo "Make sure you're running this from the CRS root directory"
    exit 1
fi

# Handle command line arguments
case "$1" in
    --help|-h)
        show_help
        exit 0
        ;;
    --list|-l)
        list_sources
        exit 0
        ;;
    "")
        # No arguments - show all vulnerabilities
        show_vulns
        exit 0
        ;;
    *)
        SOURCE="$1"
        VULN_ID="$2"
        
        # Validate inputs
        if [[ -z "$SOURCE" ]]; then
            echo "Error: Source cannot be empty"
            exit 1
        fi
        
        # Check if empty argument was passed for vuln_id
        if [[ "$VULN_ID" == "''" || "$VULN_ID" == "" ]]; then
            VULN_ID=""
        fi
        
        # Show what will be deleted and confirm
        confirm_delete "$SOURCE" "$VULN_ID"
        
        # Perform the deletion
        delete_vulns "$SOURCE" "$VULN_ID"
        ;;
esac

echo "✅ Cleanup complete!"
