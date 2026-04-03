import subprocess
import os
import sys
import argparse

def find_msbuild():
    """
    Locates MSBuild.exe using vswhere.exe.
    """
    vswhere_path = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if not os.path.exists(vswhere_path):
        # Fallback to PATH if not at default location
        try:
            subprocess.run(["vswhere", "-? shell"], capture_output=True)
            vswhere_path = "vswhere"
        except:
            return None
    
    try:
        # Find the installation path of MSBuild
        # Special thanks to the -find flag which simplifies path discovery
        result = subprocess.run([
            vswhere_path, 
            "-latest", 
            "-products", "*", 
            "-requires", "Microsoft.Component.MSBuild", 
            "-find", r"MSBuild\**\Bin\MSBuild.exe"
        ], capture_output=True, text=True, check=True)
        
        paths = result.stdout.strip().split('\n')
        for path in paths:
            if path and os.path.exists(path):
                return path
            
    except Exception as e:
        print(f"Error finding MSBuild: {e}")
        
    return None

def main():
    parser = argparse.ArgumentParser(description="Multi-functional Build Script for xsdk Project")
    parser.add_argument("-c", "--config", choices=["Debug", "Release"], default="Release", help="Build configuration (Default: Release)")
    parser.add_argument("-p", "--platform", choices=["x64", "x86"], default="x64", help="Build platform (Default: x64)")
    parser.add_argument("-v", "--variant", choices=["None", "Clang", "VMProtect", "Clang_VMProtect"], default="None", help="Build variant (Default: None)")
    parser.add_argument("-r", "--rebuild", action="store_true", help="Perform a clean and rebuild")
    parser.add_argument("-s", "--solution", default="xhunter_sdk.sln", help="Solution file to build")
    
    args = parser.parse_args()
    
    msbuild_path = find_msbuild()
    if not msbuild_path:
        print("Error: Could not locate MSBuild.exe automatically.")
        print("Please ensure Visual Studio with C++ workloads is installed.")
        sys.exit(1)
        
    print(f"[*] Found MSBuild: {msbuild_path}")
    
    # Construct the configuration string
    # Patterns in .sln: Release|x64, Release_Clang|x64, etc.
    config_str = args.config
    if args.variant != "None":
        config_str += f"_{args.variant}"
        
    full_config = f"{config_str}|{args.platform}"
    
    if not os.path.exists(args.solution):
        print(f"Error: Solution file '{args.solution}' not found.")
        sys.exit(1)
        
    print(f"[*] Building {args.solution} ({full_config})...")
    
    cmd = [
        msbuild_path,
        args.solution,
        f"/p:Configuration={config_str}",
        f"/p:Platform={args.platform}",
        "/m",             # Multi-processor build
        "/v:minimal",      # Minimal verbosity
        "/nologo"          # No logo
    ]
    
    if args.rebuild:
        cmd.append("/t:Rebuild")
    else:
        cmd.append("/t:Build")
        
    print(f"[*] Executing: {' '.join(cmd)}")
    
    try:
        # Use shell=True for better handling of paths with spaces if needed, 
        # but subprocess list handled it well.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        for line in process.stdout:
            print(line, end="")
            
        process.wait()
        
        if process.returncode == 0:
            print("\n[+] Build successful!")
        else:
            print(f"\n[-] Build failed with exit code: {process.returncode}")
            sys.exit(process.returncode)
            
    except KeyboardInterrupt:
        print("\n[!] Build interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
