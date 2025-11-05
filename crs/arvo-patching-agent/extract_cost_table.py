#!/usr/bin/env python3
"""
Extract cost analysis from workflow_data.json files into a table for analysis.

Usage:
    python extract_cost_table.py arvo_3408 arvo_20061 ...
    python extract_cost_table.py --all  # Process all arvo_* directories
"""

import json
import sys
from pathlib import Path
import csv


def extract_cost_data(arvo_id: str, workflow_file: Path) -> dict:
    """Extract cost analysis data from a single workflow_data.json file."""
    
    with open(workflow_file, 'r') as f:
        data = json.load(f)
    
    # Get basic info
    vuln_id = data.get('vuln_id', '')
    project = data.get('pov_run_data', {}).get('project_name', '')
    vuln_function = data.get('analyzed_vuln', {}).get('function', '')
    vuln_file = data.get('analyzed_vuln', {}).get('file', '')
    
    # Get cost analysis
    cost_analysis = data.get('cost_analysis', {})
    triage = cost_analysis.get('triage', {})
    patching = cost_analysis.get('patching', {})
    total = cost_analysis.get('total', {})
    
    # Get patch result
    patch_result = data.get('patch_result', {})
    patch_success = patch_result.get('success', False)
    
    # Extract pricing rates from first LLM call (if available)
    triage_calls = triage.get('llm_calls', [])
    patching_calls = patching.get('llm_calls', [])
    
    # Get pricing from first call that has it
    input_price = None
    output_price = None
    cache_price = None
    model_name = None
    
    for call in triage_calls + patching_calls:
        if call.get('input_cost_per_token'):
            input_price = call['input_cost_per_token']
            output_price = call['output_cost_per_token']
            cache_price = call['cache_cost_per_token']
            model_name = call['model']
            break
    
    return {
        # Identifiers
        'arvo_id': arvo_id,
        'vuln_id': vuln_id,
        'project': project,
        'vuln_function': vuln_function,
        'vuln_file': vuln_file,
        
        # Total costs
        'total_cost': total.get('total_cost', 0),
        'total_llm_calls': total.get('total_llm_calls', 0),
        'total_input_tokens': total.get('total_input_tokens', 0),
        'total_output_tokens': total.get('total_output_tokens', 0),
        
        # Triage phase
        'triage_cost': triage.get('total_cost', 0),
        'triage_llm_calls': triage.get('total_llm_calls', 0),
        'triage_input_tokens': triage.get('total_input_tokens', 0),
        'triage_output_tokens': triage.get('total_output_tokens', 0),
        'triage_cached_tokens': triage.get('total_cached_tokens', 0),
        
        # Patching phase
        'patching_cost': patching.get('total_cost', 0),
        'patching_llm_calls': patching.get('total_llm_calls', 0),
        'patching_input_tokens': patching.get('total_input_tokens', 0),
        'patching_output_tokens': patching.get('total_output_tokens', 0),
        'patching_cached_tokens': patching.get('total_cached_tokens', 0),
        
        # Results
        'patch_success': patch_success,
        
        # Pricing info (from actual calls)
        'model': model_name or '',
        'input_cost_per_token': input_price or 0,
        'output_cost_per_token': output_price or 0,
        'cache_cost_per_token': cache_price or 0,
        
        # Calculated metrics
        'cost_per_input_token_actual': triage.get('total_cost', 0) / triage.get('total_input_tokens', 1) if triage.get('total_input_tokens', 0) > 0 else 0,
        'cache_savings': (triage.get('total_cached_tokens', 0) * (input_price - cache_price) if input_price and cache_price else 0) +
                        (patching.get('total_cached_tokens', 0) * (input_price - cache_price) if input_price and cache_price else 0),
    }


def main():
    """Main function to extract data from all specified ARVO directories."""
    
    script_dir = Path(__file__).parent
    
    # Get list of ARVO IDs to process
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        # Find all arvo_* directories
        arvo_dirs = sorted([d for d in script_dir.glob('arvo_*') if d.is_dir()])
        arvo_ids = [d.name.replace('arvo_', '') for d in arvo_dirs]
    elif len(sys.argv) > 1:
        # Use specified ARVO IDs
        arvo_ids = sys.argv[1:]
    else:
        print("Usage: python extract_cost_table.py <arvo_id> [arvo_id ...]")
        print("   or: python extract_cost_table.py --all")
        sys.exit(1)
    
    # Extract data from all workflows
    all_data = []
    for arvo_id in arvo_ids:
        workflow_file = script_dir / f"arvo_{arvo_id}" / "workflow_data.json"
        
        if not workflow_file.exists():
            print(f"⚠️  Skipping {arvo_id}: No workflow_data.json found", file=sys.stderr)
            continue
        
        try:
            data = extract_cost_data(arvo_id, workflow_file)
            all_data.append(data)
            print(f"✓ Processed arvo_{arvo_id}", file=sys.stderr)
        except Exception as e:
            print(f"✗ Error processing {arvo_id}: {e}", file=sys.stderr)
    
    if not all_data:
        print("No data extracted!", file=sys.stderr)
        sys.exit(1)
    
    # Write to CSV
    output_file = script_dir / "cost_analysis_table.csv"
    
    fieldnames = [
        'arvo_id', 'vuln_id', 'project', 'vuln_function', 'vuln_file',
        'total_cost', 'total_llm_calls', 'total_input_tokens', 'total_output_tokens',
        'triage_cost', 'triage_llm_calls', 'triage_input_tokens', 'triage_output_tokens', 'triage_cached_tokens',
        'patching_cost', 'patching_llm_calls', 'patching_input_tokens', 'patching_output_tokens', 'patching_cached_tokens',
        'patch_success', 'model',
        'input_cost_per_token', 'output_cost_per_token', 'cache_cost_per_token',
        'cost_per_input_token_actual', 'cache_savings'
    ]
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_data)
    
    print(f"\n✓ Wrote {len(all_data)} rows to {output_file}", file=sys.stderr)
    
    # Also print summary statistics
    print("\n" + "="*80, file=sys.stderr)
    print("SUMMARY STATISTICS", file=sys.stderr)
    print("="*80, file=sys.stderr)
    
    total_cost_sum = sum(d['total_cost'] for d in all_data)
    successful_patches = sum(1 for d in all_data if d['patch_success'])
    
    print(f"Total samples: {len(all_data)}", file=sys.stderr)
    print(f"Successful patches: {successful_patches} ({successful_patches/len(all_data)*100:.1f}%)", file=sys.stderr)
    print(f"Total cost: ${total_cost_sum:.4f}", file=sys.stderr)
    print(f"Average cost per sample: ${total_cost_sum/len(all_data):.4f}", file=sys.stderr)
    print(f"Min cost: ${min(d['total_cost'] for d in all_data):.4f}", file=sys.stderr)
    print(f"Max cost: ${max(d['total_cost'] for d in all_data):.4f}", file=sys.stderr)
    
    # Estimate for 1.8K samples
    avg_cost = total_cost_sum / len(all_data)
    print(f"\n📊 PROJECTION FOR 1,800 SAMPLES:", file=sys.stderr)
    print(f"Estimated total cost: ${avg_cost * 1800:.2f}", file=sys.stderr)
    print(f"  (Based on average of ${avg_cost:.4f} per sample)", file=sys.stderr)
    print("="*80, file=sys.stderr)


if __name__ == "__main__":
    main()

