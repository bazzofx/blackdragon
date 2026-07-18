#!/usr/bin/env python3
import os
import sys
import glob
import subprocess

def run_script(script_name, args):
    """
    Runs a python script as a subprocess with specified arguments.
    """
    cmd = [sys.executable, script_name] + args
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False, text=True)
    if result.returncode != 0:
        print(f"Error: {script_name} failed with exit code {result.returncode}")
        return False
    return True

def main():
    # 1. Determine script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Locate paths of verify.py and report.py relative to this script
    verify_script = os.path.join(script_dir, 'verify.py')
    report_script = os.path.join(script_dir, 'report.py')
    
    if not os.path.exists(verify_script) or not os.path.exists(report_script):
        print("Error: verify.py or report.py not found in the script directory.")
        sys.exit(1)
        
    # 2. Parse custom command-line inputs or fall back to auto-discovering files
    args = sys.argv[1:]
    input_files = []
    
    for arg in args:
        if arg.endswith('.csv') and not arg.endswith('_clean.csv') and not arg.endswith('_verified.csv'):
            input_files.append(arg)
            
    # Auto-discovery if no files specified
    if not input_files:
        print("No CSV files specified. Auto-detecting targets in directory...")
        all_csvs = glob.glob(os.path.join(script_dir, '*.csv'))
        
        # We look for files like luizcalixt0.csv and robsonsaint.csv
        # Exclude verified outputs and Maltego exports
        for f in all_csvs:
            base = os.path.basename(f)
            if not base.endswith('_verified.csv') and not base.endswith('_clean.csv') and not base.endswith('_maltego.csv') and base != 'verified.csv':
                input_files.append(f)
                
    if len(input_files) < 2:
        print(f"Error: Need at least 2 CSV files to correlate. Discovered: {input_files}")
        sys.exit(1)
        
    print(f"Targets discovered for processing: {[os.path.basename(f) for f in input_files]}")
    
    # 3. Verify each CSV file (filter false positives)
    verified_files = []
    for csv_file in input_files:
        dir_name = os.path.dirname(csv_file)
        base_name = os.path.basename(csv_file)
        name_part = os.path.splitext(base_name)[0]
        
        # Save as _clean.csv to avoid locks on _verified.csv
        verified_path = os.path.join(dir_name, f"{name_part}_clean.csv")
        
        print(f"\n--- Verifying {base_name} ---")
        success = run_script(verify_script, [csv_file, verified_path])
        if not success:
            print("Aborting pipeline due to verification error.")
            sys.exit(1)
            
        verified_files.append(verified_path)
        
    # 4. Generate the aggregated HTML correlation report
    output_html = os.path.join(script_dir, 'osint_correlation_report.html')
    print(f"\n--- Correlating Footprints and Generating Report ---")
    success = run_script(report_script, verified_files + [output_html])
    
    if success:
        print(f"\nPipeline successfully completed! Visualizer report saved at:")
        # Replaced emoji with safe string
        print(f"[REPORT]: {output_html}")
    else:
        print("\nPipeline failed during report compilation.")
        sys.exit(1)

if __name__ == '__main__':
    main()
