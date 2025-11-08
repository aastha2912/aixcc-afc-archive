#!/usr/bin/env python3
"""
Standalone script to count tokens in ARVO Docker images.

This script:
1. Reads ARVO IDs from github_ids.csv
2. For each ID, uses the ARVO Docker image (n132/arvo:{id}-vul)
3. Extracts source code from the image
4. Counts tokens
5. Saves results to token_counts_summary.csv

Requirements:
- Docker installed and running
- litellm (pip install litellm)

Usage:
    python standalone_count_arvo_tokens.py
    
Features:
- Auto-resume: Always skips already processed IDs
- Retry logic: 3 attempts for transient failures (network, Docker issues)
- Continue on error: One failure won't stop the entire pipeline
- Progress saved: Results saved after each ID (never lose progress)
"""

import csv
import json
import subprocess
import sys
import tempfile
import tarfile
import time
from pathlib import Path
from collections import defaultdict


# File extensions to count (match crs/common/constants.py)
C_EXTENSIONS = {'.ixx', '.ipp', '.ino', '.h++', '.cxx', '.cats', '.inl', '.h', '.cc', '.hxx', '.c', '.cpp', '.inc', '.idc', '.tpp', '.hpp', '.cp', '.c++', '.tcc', '.cppm', '.txx', '.re', '.hh'}
JAVA_EXTENSIONS = {'.java', '.jav', '.jsh'}


def count_tokens(text, model="gpt-4o-mini"):
    """Count tokens using litellm"""
    try:
        import litellm
        tokens = litellm.encode(model, text)
        return len(tokens)
    except:
        # Fallback: rough estimate (1 token ≈ 4 characters)
        return len(text) // 4


def docker_image_exists(image_name):
    """Check if Docker image exists locally"""
    result = subprocess.run(
        ['docker', 'image', 'inspect', image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def pull_docker_image(image_name):
    """Pull Docker image"""
    print(f"  Pulling image: {image_name}")
    result = subprocess.run(
        ['docker', 'pull', image_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.returncode == 0


def extract_source_from_docker(arvo_id, retry_count=0):
    """Extract source code from ARVO Docker image and count tokens"""
    
    image_name = f"n132/arvo:{arvo_id}-vul"
    max_retries = 3
    
    # Check if image exists, pull if needed
    if not docker_image_exists(image_name):
        print(f"  Image not found locally, pulling...")
        if not pull_docker_image(image_name):
            # Retry on pull failure
            if retry_count < max_retries:
                print(f"  Retrying pull... (attempt {retry_count + 1}/{max_retries})")
                time.sleep(2)
                return extract_source_from_docker(arvo_id, retry_count + 1)
            return None, "Failed to pull Docker image after retries"
    
    # Create temporary directory for extraction
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        tar_file = tmpdir / "src.tar"
        
        # Extract /src directory from Docker image
        print(f"  Extracting source code from image...")
        try:
            # Run container and copy /src to tar
            result = subprocess.run(
                [
                    'docker', 'run', '--rm', image_name,
                    'tar', 'cf', '-', '-C', '/src', '.'
                ],
                stdout=open(tar_file, 'wb'),
                stderr=subprocess.PIPE,
                timeout=120
            )
            
            if result.returncode != 0:
                # Retry on extraction failure
                if retry_count < max_retries:
                    print(f"  Retrying extraction... (attempt {retry_count + 1}/{max_retries})")
                    time.sleep(2)
                    return extract_source_from_docker(arvo_id, retry_count + 1)
                return None, f"Failed to extract /src from image after retries"
            
            if not tar_file.exists() or tar_file.stat().st_size == 0:
                return None, "Extracted tar is empty"
            
        except subprocess.TimeoutExpired:
            # Retry on timeout
            if retry_count < max_retries:
                print(f"  Retrying after timeout... (attempt {retry_count + 1}/{max_retries})")
                time.sleep(5)
                return extract_source_from_docker(arvo_id, retry_count + 1)
            return None, "Extraction timeout after retries"
        except Exception as e:
            return None, f"Extraction error: {str(e)[:100]}"
        
        # Count tokens in the tar file
        print(f"  Counting tokens...")
        try:
            file_tokens = {}
            total_tokens = 0
            total_chars = 0
            files_by_extension = defaultdict(int)
            
            with tarfile.open(tar_file, 'r') as tar:
                members = tar.getmembers()
                source_members = [
                    m for m in members 
                    if m.isfile() and any(m.name.endswith(ext) for ext in C_EXTENSIONS | JAVA_EXTENSIONS)
                ]
                
                if not source_members:
                    return None, "No source files found in /src"
                
                for member in source_members:
                    try:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8', errors='replace')
                            token_count = count_tokens(content)
                            
                            total_tokens += token_count
                            total_chars += len(content)
                            
                            ext = Path(member.name).suffix
                            files_by_extension[ext] += 1
                    except:
                        continue
            
            result = {
                'total_tokens': total_tokens,
                'total_files': len(source_members),
                'total_chars': total_chars,
                'avg_tokens_per_file': total_tokens // len(source_members) if source_members else 0,
                'breakdown': dict(files_by_extension)
            }
            
            return result, None
            
        except Exception as e:
            return None, f"Token counting error: {str(e)[:100]}"


def load_ids(csv_file='github_ids.csv'):
    """Load ARVO IDs from CSV"""
    ids = []
    
    if not Path(csv_file).exists():
        print(f"Error: {csv_file} not found!")
        sys.exit(1)
    
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            arvo_id = row.get('id', '').strip()
            if arvo_id:
                ids.append(arvo_id)
    
    return ids


def check_already_processed(arvo_id, results_file='token_counts_summary.csv'):
    """Check if ID already processed"""
    if not Path(results_file).exists():
        return False
    
    try:
        with open(results_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('arvo_id') == arvo_id and row.get('status') == 'success':
                    return True
    except:
        pass
    
    return False


def save_result(arvo_id, result, error, results_file='token_counts_summary.csv'):
    """Append result to CSV"""
    
    file_exists = Path(results_file).exists()
    
    with open(results_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'arvo_id', 'status', 'total_tokens', 'total_files', 
            'total_chars', 'avg_tokens_per_file', 'error'
        ])
        
        if not file_exists:
            writer.writeheader()
        
        if result:
            writer.writerow({
                'arvo_id': arvo_id,
                'status': 'success',
                'total_tokens': result['total_tokens'],
                'total_files': result['total_files'],
                'total_chars': result['total_chars'],
                'avg_tokens_per_file': result['avg_tokens_per_file'],
                'error': ''
            })
        else:
            writer.writerow({
                'arvo_id': arvo_id,
                'status': 'failed',
                'total_tokens': 0,
                'total_files': 0,
                'total_chars': 0,
                'avg_tokens_per_file': 0,
                'error': error
            })


def main():
    # Always run in resume mode (skip already processed)
    resume_mode = True
    
    print("="*80)
    print("ARVO TOKEN COUNTER (Standalone)")
    print("="*80)
    print(f"Robust mode: Auto-resume, retry on failures, continue on errors\n")
    
    # Load IDs
    print("Loading IDs from github_ids.csv...")
    ids = load_ids()
    print(f"Found {len(ids)} IDs\n")
    
    # Always filter already processed (auto-resume)
    original_count = len(ids)
    ids = [id for id in ids if not check_already_processed(id)]
    skipped = original_count - len(ids)
    
    if skipped > 0:
        print(f"Skipping {skipped} already processed IDs")
    print(f"Will process {len(ids)} IDs\n")
    
    if not ids:
        print("All IDs already processed!")
        return
    
    # Process each ID
    print("="*80)
    print("PROCESSING")
    print("="*80)
    
    success_count = 0
    error_count = 0
    
    for i, arvo_id in enumerate(ids, 1):
        print(f"\n[{i}/{len(ids)}] Processing ARVO {arvo_id}...")
        
        try:
            # This will retry up to 3 times on transient failures
            result, error = extract_source_from_docker(arvo_id)
            
            if result:
                print(f"  ✓ Success: {result['total_tokens']:,} tokens in {result['total_files']} files")
                success_count += 1
            else:
                print(f"  ✗ Failed: {error}")
                error_count += 1
            
            # Save result immediately (append mode) - so progress is never lost
            save_result(arvo_id, result, error)
            
        except KeyboardInterrupt:
            # Allow user to stop gracefully
            print(f"\n\n⚠️  Interrupted by user at ID {arvo_id}")
            print(f"Progress saved. Run again to continue from ID {arvo_id}")
            raise
            
        except Exception as e:
            # Catch any exception, log it, but continue processing
            print(f"  ✗ Exception: {str(e)[:100]}")
            save_result(arvo_id, None, str(e)[:200])
            error_count += 1
            # Continue to next ID - don't stop entire pipeline
    
    # Final summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total processed: {len(ids)}")
    print(f"Successful: {success_count} ({success_count/len(ids)*100:.1f}%)")
    print(f"Failed: {error_count} ({error_count/len(ids)*100:.1f}%)")
    print(f"\nResults saved to: token_counts_summary.csv")
    print("="*80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        print("Run with --resume to continue")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

