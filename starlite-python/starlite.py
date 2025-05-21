import time
import scanner_logic
import sys
import os
import asyncio
import resource
from urlhaus import fetch_and_extract_ips

OUT_FILE = "ips.txt"
BLACKLIST = ["1.1.1.1"]
TEMP_FILTERED_IPS_FILE = "starlite_filtered_ips.tmp"

def increase_file_limit():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        print(f"[starlite] increased file descriptor limit to {hard}")
    except (ValueError, resource.error) as e:
        print(f"[starlite] WARNING: could not increase file descriptor limit: {e}")

async def run_scan_cycle():
    print(f"[starlite] starting scan cycle...")
    
    print("[starlite] fetching fresh IPs from URLhaus...")
    fetch_and_extract_ips(OUT_FILE)
            
    all_ips = []
    try:
        with open(OUT_FILE, 'r') as f_in:
            all_ips = [line.strip() for line in f_in if line.strip()]
    except FileNotFoundError:
        print(f"[starlite] ERROR: IP source file '{OUT_FILE}' disappeared. Skipping cycle, will retry in 5s.")
        await asyncio.sleep(5)
        return
    except Exception as e_read:
        print(f"[starlite] ERROR: Could not read IP source file '{OUT_FILE}': {e_read}. Skipping cycle, will retry in 5s.")
        await asyncio.sleep(5)
        return

    if not all_ips:
        print(f"[starlite] IP source file '{OUT_FILE}' is currently empty or contains no valid IP lines. Skipping scan for this cycle.")
    else:
        ips_to_scan = [ip for ip in all_ips if ip not in BLACKLIST]
        #print(f"[starlite] IPs read from {OUT_FILE}: {all_ips}")
        #print(f"[starlite] Blacklist: {BLACKLIST}")
        #print(f"[starlite] IPs to scan after filtering: {ips_to_scan}")

        if not ips_to_scan:
            if all_ips:
                print(f"[starlite] All {len(all_ips)} IPs from '{OUT_FILE}' are blacklisted. No IPs to scan this cycle.")
        else:
            try:
                with open(TEMP_FILTERED_IPS_FILE, 'w') as f_out:
                    for ip in ips_to_scan:
                        f_out.write(ip + "\n")
                
                #print(f"[starlite] Wrote {len(ips_to_scan)} IPs to {TEMP_FILTERED_IPS_FILE}: {ips_to_scan}")
                print(f"[starlite] scanning {len(ips_to_scan)} IPs (from {len(all_ips)} total in '{OUT_FILE}') after applying blacklist")
                await scanner_logic.scan_ips_from_file_async(TEMP_FILTERED_IPS_FILE)
            except Exception as e_scan_write:
                print(f"[starlite] error during filtered scan or temp file operation: {e_scan_write}")
            finally:
                if os.path.exists(TEMP_FILTERED_IPS_FILE):
                    try:
                        os.remove(TEMP_FILTERED_IPS_FILE)
                    except OSError as e_remove:
                        print(f"[starlite] WARNING: could not delete temporary file {TEMP_FILTERED_IPS_FILE}: {e_remove}")
    
    print(f"[starlite] scan cycle finished, sleeping for 1 second")
    await asyncio.sleep(1)

def main():
    print(f"[starlite] initializing Scanner...")
    #print(f"[starlite] Blacklist active. IPs such as {BLACKLIST[0] if BLACKLIST else 'any in blacklist'} will be skipped.")
    print(f"[starlite] IP source file: {OUT_FILE}")

    increase_file_limit()

    if not os.path.exists(OUT_FILE):
        print(f"[starlite] CRITICAL ERROR: the IP address file '{OUT_FILE}' was not found at startup")
        sys.exit(1)
    
    try:
        while True:
            asyncio.run(run_scan_cycle())
            
    except KeyboardInterrupt:
        print("\n[starlite] scanner interrupted by user, exiting")
        if os.path.exists(TEMP_FILTERED_IPS_FILE):
            try:
                os.remove(TEMP_FILTERED_IPS_FILE)
                print(f"[starlite] cleaned up {TEMP_FILTERED_IPS_FILE} on exit")
            except OSError:
                print(f"[starlite] WARNING: could not delete {TEMP_FILTERED_IPS_FILE} on exit")
        sys.exit(0)
    except Exception as e:
        print(f"[starlite] An unexpected critical error occurred: {e}")
        if os.path.exists(TEMP_FILTERED_IPS_FILE):
            try:
                os.remove(TEMP_FILTERED_IPS_FILE)
                print(f"[starlite] cleaned up {TEMP_FILTERED_IPS_FILE} on error exit")
            except OSError:
                print(f"[starlite] WARNING: could not delete {TEMP_FILTERED_IPS_FILE} on error exit")
        sys.exit(1)

if __name__ == "__main__":
    main() 
