#!/usr/bin/env python3
"""
Script to show the full patch content from the database
"""
import sqlite3
from pathlib import Path

def show_patch():
    """Show the full patch content from the database"""
    db_path = Path("data/products.sqlite3")
    
    if not db_path.exists():
        print("❌ Database not found")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get the patch content
        cursor.execute("""
            SELECT id, task_uuid, project_name, vuln_id, diff
            FROM patches 
            ORDER BY id DESC
            LIMIT 1
        """)
        
        patch_data = cursor.fetchone()
        
        if not patch_data:
            print("❌ No patches found")
            conn.close()
            return
        
        patch_id, task_uuid, project_name, vuln_id, diff_content = patch_data
        
        print(f"🔍 Patch Details:")
        print(f"   ID: {patch_id}")
        print(f"   Task UUID: {task_uuid}")
        print(f"   Project: {project_name}")
        print(f"   Vulnerability ID: {vuln_id}")
        print(f"   Patch Length: {len(diff_content)} characters")
        
        print(f"\n📝 Full Patch Content:")
        print("=" * 80)
        print(diff_content)
        print("=" * 80)
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    show_patch()
