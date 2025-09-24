#!/bin/bash

# CRS Task Status Viewer
# Shows all tasks in the database with their statuses and useful information

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== CRS Task Status Report ===${NC}"
echo "Generated at: $(date)"
echo ""

# Check if databases exist
if [[ ! -f "$DATA_DIR/tasks.sqlite3" ]]; then
    echo -e "${RED}Error: tasks.sqlite3 not found in $DATA_DIR${NC}"
    exit 1
fi

if [[ ! -f "$DATA_DIR/work.sqlite3" ]]; then
    echo -e "${RED}Error: work.sqlite3 not found in $DATA_DIR${NC}"
    exit 1
fi

# Function to get status name from status code
get_status_name() {
    case $1 in
        0) echo "PENDING" ;;
        1) echo "RUNNING" ;;
        2) echo "COMPLETED" ;;
        3) echo "FAILED" ;;
        4) echo "CANCELLED" ;;
        *) echo "UNKNOWN($1)" ;;
    esac
}

# Function to get work type name
get_work_type() {
    case $1 in
        0) echo "LAUNCH_TASK" ;;
        1) echo "BUILD_IMAGE" ;;
        2) echo "RUN_FUZZER" ;;
        3) echo "ANALYZE_RESULTS" ;;
        4) echo "GENERATE_REPORT" ;;
        *) echo "UNKNOWN($1)" ;;
    esac
}

echo -e "${BLUE}=== TASK OVERVIEW ===${NC}"
echo ""

# Get task count
TASK_COUNT=$(sqlite3 "$DATA_DIR/tasks.sqlite3" "SELECT COUNT(*) FROM tasks;")
echo -e "${GREEN}Total Tasks: $TASK_COUNT${NC}"

# Get job count by status
echo -e "\n${YELLOW}Job Status Summary:${NC}"
sqlite3 "$DATA_DIR/work.sqlite3" "
SELECT 
    status,
    COUNT(*) as count
FROM jobs 
GROUP BY status 
ORDER BY status;
" | while IFS='|' read -r status count; do
    status_name=$(get_status_name $status)
    echo -e "  $status_name: $count"
done

echo ""

# Show detailed task information
if [[ $TASK_COUNT -gt 0 ]]; then
    echo -e "${BLUE}=== DETAILED TASK INFORMATION ===${NC}"
    echo ""
    
    # Get task details
    sqlite3 "$DATA_DIR/tasks.sqlite3" "
    SELECT 
        id,
        message_id,
        json
    FROM tasks
    ORDER BY id;
    " | while IFS='|' read -r task_id message_id json; do
        echo -e "${PURPLE}Task ID: $task_id${NC}"
        echo -e "${CYAN}Message ID: $message_id${NC}"
        
        # Parse JSON to get task details (basic parsing)
        project_name=$(echo "$json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('tasks', [{}])[0].get('project_name', 'Unknown'))" 2>/dev/null || echo "Unknown")
        task_type=$(echo "$json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('tasks', [{}])[0].get('type', 'Unknown'))" 2>/dev/null || echo "Unknown")
        focus=$(echo "$json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('tasks', [{}])[0].get('focus', 'Unknown'))" 2>/dev/null || echo "Unknown")
        
        echo -e "  Project: ${GREEN}$project_name${NC}"
        echo -e "  Type: ${YELLOW}$task_type${NC}"
        echo -e "  Focus: ${YELLOW}$focus${NC}"
        
        # Get job information for this task
        echo -e "  ${BLUE}Jobs:${NC}"
        sqlite3 "$DATA_DIR/work.sqlite3" "
        SELECT 
            id,
            status,
            worktype,
            failure_count,
            added,
            priority
        FROM jobs 
        WHERE task_id = '$task_id'
        ORDER BY added;
        " | while IFS='|' read -r job_id status worktype failure_count added priority; do
            status_name=$(get_status_name $status)
            work_type=$(get_work_type $worktype)
            echo -e "    Job $job_id: $work_type - $status_name (failures: $failure_count, priority: $priority)"
            echo -e "      Added: $added"
        done
        
        echo ""
    done
fi

# Show recent job activity
echo -e "${BLUE}=== RECENT JOB ACTIVITY ===${NC}"
echo ""

sqlite3 "$DATA_DIR/work.sqlite3" "
SELECT 
    j.id,
    j.task_id,
    j.status,
    j.worktype,
    j.failure_count,
    j.added,
    j.priority
FROM jobs j
ORDER BY j.added DESC
LIMIT 10;
" | while IFS='|' read -r job_id task_id status worktype failure_count added priority; do
    status_name=$(get_status_name $status)
    work_type=$(get_work_type $worktype)
    echo -e "Job $job_id (Task: ${task_id:0:8}...): $work_type - $status_name"
    echo -e "  Added: $added, Failures: $failure_count, Priority: $priority"
    echo ""
done

# Show failed jobs
echo -e "${RED}=== FAILED JOBS ===${NC}"
echo ""

FAILED_COUNT=$(sqlite3 "$DATA_DIR/work.sqlite3" "SELECT COUNT(*) FROM jobs WHERE status = 3;")
if [[ $FAILED_COUNT -gt 0 ]]; then
    sqlite3 "$DATA_DIR/work.sqlite3" "
    SELECT 
        j.id,
        j.task_id,
        j.worktype,
        j.failure_count,
        j.added
    FROM jobs j
    WHERE j.status = 3
    ORDER BY j.added DESC;
    " | while IFS='|' read -r job_id task_id worktype failure_count added; do
        work_type=$(get_work_type $worktype)
        echo -e "${RED}Job $job_id (Task: ${task_id:0:8}...): $work_type${NC}"
        echo -e "  Added: $added, Failures: $failure_count"
        echo ""
    done
else
    echo -e "${GREEN}No failed jobs found!${NC}"
fi

echo -e "${CYAN}=== END OF REPORT ===${NC}"
