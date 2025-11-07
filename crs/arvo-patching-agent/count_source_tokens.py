#!/usr/bin/env python3
"""
Count total tokens in source code for a given ARVO ID.

Usage:
    python count_source_tokens.py <ARVO_ID>
"""

import json
import sys
import tarfile
import tempfile
from pathlib import Path
from collections import defaultdict

# Add to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crs.common.constants import C_EXTENSIONS, JAVA_EXTENSIONS


def load_arvo_config(arvo_id: str) -> dict:
    """Load configuration from ARVO config file"""
    script_dir = Path(__file__).parent
    config_file = script_dir / f"arvo_{arvo_id}" / "config.json"
    
    if not config_file.exists():
        print(f"Error: Configuration file not found: {config_file}")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        return json.load(f)


def count_tokens(text: str, model: str = "gpt-4o-mini") -> int:
    """Count tokens using litellm"""
    try:
        import litellm
        tokens = litellm.encode(model, text)
        return len(tokens)
    except:
        # Fallback: rough estimate
        return len(text) // 4


def main():
    if len(sys.argv) < 2:
        print("Usage: python count_source_tokens.py <ARVO_ID>")
        sys.exit(1)
    
    arvo_id = sys.argv[1]
    config = load_arvo_config(arvo_id)
    
    print(f"\n{'='*80}")
    print(f"Counting tokens for ARVO ID: {arvo_id}")
    print(f"Project: {config['project_name']}")
    print(f"{'='*80}\n")
    
    # Find the src.tar file by searching the cache
    from crs import config as crs_config
    
    project_dir = Path(config['project_dir'])
    project_name = project_dir.name
    
    # Search for src.tar in cache directory
    cache_dir = Path(crs_config.CACHE_DIR) / "data"
    src_tar = None
    
    if cache_dir.exists():
        # Look for any src.tar for this project
        for hash_dir in cache_dir.iterdir():
            if hash_dir.is_dir():
                project_cache = hash_dir / project_name
                candidate = project_cache / "src.tar"
                if candidate.exists():
                    src_tar = candidate
                    break
    
    if not src_tar:
        print(f"Error: src.tar not found in cache for project {project_name}")
        print(f"Searched in: {cache_dir}")
        print("Run the ARVO integration script first.")
        sys.exit(1)
    
    print(f"Reading source from: {src_tar}")
    
    # Determine language and extensions
    project_yaml = project_dir / "project.yaml"
    import yaml
    with open(project_yaml) as f:
        project_info = yaml.safe_load(f)
    
    language = project_info.get('language', 'c')
    extensions = JAVA_EXTENSIONS if language == 'jvm' else C_EXTENSIONS
    
    print(f"Language: {language}")
    print(f"Scanning for files with extensions: {', '.join(sorted(extensions))}\n")
    
    # Count tokens from tar file
    file_tokens = {}
    total_tokens = 0
    total_chars = 0
    files_by_extension = defaultdict(list)
    
    with tarfile.open(src_tar, 'r') as tar:
        members = tar.getmembers()
        source_members = [m for m in members if m.isfile() and any(m.name.endswith(ext) for ext in extensions)]
        
        print(f"Found {len(source_members)} source files")
        print("Counting tokens...\n")
        
        for i, member in enumerate(source_members, 1):
            if i % 100 == 0:
                print(f"  Processed {i}/{len(source_members)} files...")
            
            try:
                # Extract and read file
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode('utf-8', errors='replace')
                    
                    # Count tokens
                    token_count = count_tokens(content)
                    
                    file_tokens[member.name] = {
                        'tokens': token_count,
                        'chars': len(content),
                        'lines': content.count('\n') + 1
                    }
                    
                    total_tokens += token_count
                    total_chars += len(content)
                    
                    # Group by extension
                    ext = Path(member.name).suffix
                    files_by_extension[ext].append(member.name)
            
            except Exception as e:
                print(f"  Warning: Could not process {member.name}: {e}")
    
    # Print results
    print(f"\n{'='*80}")
    print("RESULTS")
    print(f"{'='*80}")
    print(f"Total source files: {len(file_tokens):,}")
    print(f"Total tokens: {total_tokens:,}")
    print(f"Total characters: {total_chars:,}")
    print(f"Average tokens per file: {total_tokens // len(file_tokens):,}")
    print(f"Average characters per token: {total_chars / total_tokens:.2f}")
    
    # Breakdown by extension
    print(f"\n{'='*80}")
    print("BREAKDOWN BY FILE TYPE")
    print(f"{'='*80}")
    for ext in sorted(files_by_extension.keys()):
        files = files_by_extension[ext]
        ext_tokens = sum(file_tokens[f]['tokens'] for f in files)
        print(f"{ext:<10} {len(files):>6} files    {ext_tokens:>12,} tokens")
    
    # Top 10 largest files
    print(f"\n{'='*80}")
    print("TOP 10 LARGEST FILES BY TOKEN COUNT")
    print(f"{'='*80}")
    sorted_files = sorted(file_tokens.items(), key=lambda x: x[1]['tokens'], reverse=True)[:10]
    for file_path, stats in sorted_files:
        print(f"{stats['tokens']:>8,} tokens  {stats['lines']:>6,} lines  {file_path}")
    
    # Save results
    output_file = Path(__file__).parent / f"arvo_{arvo_id}" / "source_token_count.json"
    output_data = {
        'arvo_id': arvo_id,
        'project_name': config['project_name'],
        'language': language,
        'total_files': len(file_tokens),
        'total_tokens': total_tokens,
        'total_chars': total_chars,
        'avg_tokens_per_file': total_tokens // len(file_tokens),
        'breakdown_by_extension': {
            ext: {
                'file_count': len(files),
                'total_tokens': sum(file_tokens[f]['tokens'] for f in files)
            }
            for ext, files in files_by_extension.items()
        },
        'top_10_largest_files': [
            {
                'file': file_path,
                'tokens': stats['tokens'],
                'chars': stats['chars'],
                'lines': stats['lines']
            }
            for file_path, stats in sorted_files
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"✓ Saved results to: {output_file}")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
