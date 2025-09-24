#!/bin/bash

# (aastham) CRS Task Deletion Script
# Usage: ./delete_task.sh <task_id>
# Example: ./delete_task.sh bf3b0b44-2f59-40d1-ae70-17cc5c2c438a

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if task ID is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Task ID is required${NC}"
    echo "Usage: $0 <task_id>"
    echo "Example: $0 bf3b0b44-2f59-40d1-ae70-17cc5c2c438a"
    exit 1
fi

TASK_ID="$1"
DATA_DIR="./data"

# Validate task ID format (basic UUID check)
if [[ ! $TASK_ID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo -e "${YELLOW}Warning: Task ID doesn't look like a valid UUID${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${YELLOW}Deleting task: $TASK_ID${NC}"
echo

# Check if data directory exists
if [ ! -d "$DATA_DIR" ]; then
    echo -e "${RED}Error: Data directory '$DATA_DIR' not found${NC}"
    echo "Make sure you're running this script from the CRS root directory"
    exit 1
fi

# Function to check if database exists
check_db() {
    local db_path="$1"
    if [ ! -f "$db_path" ]; then
        echo -e "${YELLOW}Warning: Database '$db_path' not found, skipping...${NC}"
        return 1
    fi
    return 0
}

# Function to delete from database
delete_from_db() {
    local db_path="$1"
    local table="$2"
    local where_clause="$3"
    local description="$4"
    
    if check_db "$db_path"; then
        echo -n "Deleting from $description... "
        local count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM $table WHERE $where_clause;")
        if [ "$count" -gt 0 ]; then
            sqlite3 "$db_path" "DELETE FROM $table WHERE $where_clause;"
            echo -e "${GREEN}✓ Deleted $count row(s)${NC}"
        else
            echo -e "${YELLOW}No rows found${NC}"
        fi
    fi
}

# Delete from tasks database
delete_from_db "$DATA_DIR/tasks.sqlite3" "tasks" "id = '$TASK_ID'" "tasks table"

# Delete from cancellations database  
delete_from_db "$DATA_DIR/tasks.sqlite3" "cancellations" "id = '$TASK_ID'" "cancellations table"

# Delete from work queue database
delete_from_db "$DATA_DIR/work.sqlite3" "jobs" "task_id = '$TASK_ID'" "work queue jobs"

echo
echo -e "${GREEN}Task deletion completed!${NC}"

# Verify cleanup
echo
echo -e "${YELLOW}Verifying cleanup:${NC}"
echo "Tasks database:"
sqlite3 "$DATA_DIR/tasks.sqlite3" "SELECT COUNT(*) as remaining_tasks FROM tasks WHERE id = '$TASK_ID';" 2>/dev/null || echo "0"
echo "Cancellations database:"
sqlite3 "$DATA_DIR/tasks.sqlite3" "SELECT COUNT(*) as remaining_cancellations FROM cancellations WHERE id = '$TASK_ID';" 2>/dev/null || echo "0"
echo "Work queue database:"
sqlite3 "$DATA_DIR/work.sqlite3" "SELECT COUNT(*) as remaining_jobs FROM jobs WHERE task_id = '$TASK_ID';" 2>/dev/null || echo "0"

echo
echo -e "${GREEN}Task $TASK_ID has been completely removed from all databases.${NC}"
