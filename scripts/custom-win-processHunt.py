import boto3
import signal
import argparse
import sys
import yaml
import json
import grpc
import requests
import time
import schedule
from socket import socket, AF_UNIX, SOCK_DGRAM
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc
from botocore.config import Config

# --- Configuration ---
CLIENT_ID = "C.4831d0446a3690cd"  # Replace with your test client_id, can be dynamic with script to be triggered on a alert and fetch from the agent ID as in previous scripts.
ARTIFACTS_TO_COLLECT = ["Windows.Memory.ProcessInfo"]
API_CONFIG_FILE = "/home/thilak/api.config.yaml"
WAZUH_SOCKET_ADDR = '/var/ossec/queue/sockets/queue'

BEDROCK_REGION = "eu-west-2"  
BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
BEDROCK_TIMEOUT = 3600

# AWS Credentials - set these as environment variables or use IAM roles
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set in environment

# --- Main SOAR Workflow ---
def run_soar_workflow():
    """Executes the full SOAR pipeline using collections + Bedrock for AI analysis."""
    
    print("\n=============================")
    print("Starting Enhanced SOAR Workflow...")
    print("=============================")

    flow_id = create_collection(CLIENT_ID, ARTIFACTS_TO_COLLECT, API_CONFIG_FILE)
    if not flow_id:
        return

    wait_for_collection(flow_id, API_CONFIG_FILE)

    results = fetch_collection_results(CLIENT_ID, flow_id, API_CONFIG_FILE)
    if not results:
        print("[!] No results fetched from collection. Exiting.")
        return

    # Reduce results for LLM consumption
    results_trimmed = reduce_results(results)
    
    print(f"Processed {len(results_trimmed)} artifacts for analysis")

    print("Part 3: Analyzing results with Claude Bedrock...")
    suspicious_summary = analyze_with_claude_bedrock(results_trimmed)
    if not suspicious_summary:
        return

    send_wazuh_alert(flow_id, suspicious_summary)


# --- Velociraptor Helper Functions ---
def run_vql_query(vql, api_config_path):
    """Connects to the Velociraptor API via gRPC and runs a VQL query."""
    try:
        with open(api_config_path, "r") as f:
            config = yaml.safe_load(f)
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8")
        )
        options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)
        with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
            stub = api_pb2_grpc.APIStub(channel)
            request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
            all_responses = []
            for response in stub.Query(request):
                if response.Response:
                    all_responses.extend(json.loads(response.Response))
            return all_responses
    except Exception as e:
        print(f"[!] An error occurred in run_vql_query: {e}")
        return None


def create_collection(client_id, artifacts, api_config_path):
    """Starts a new artifact collection on a single client."""
    print(f"\n[🏹] Part 1: Starting Collection on client {client_id}...")
    artifacts_str = json.dumps(artifacts)

    vql = f"""
    LET collection <= collect_client(
        client_id='{client_id}',
        artifacts={artifacts_str}
    )
    SELECT * FROM collection
    """

    response = run_vql_query(vql, api_config_path)
    if response:
        flow_id = response[0].get("flow_id")
        if flow_id:
            print(f"[+] Collection started. Flow ID: {flow_id}")
            return flow_id
    print("[!] Error: Could not create collection.")
    return None


def wait_for_collection(flow_id, api_config_path):
    """Blocks until the collection flow is marked as complete."""
    print(f"\n[⏳] Part 2: Waiting for collection '{flow_id}' to complete...")
    vql = f"""
    SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
    WHERE FlowId = '{flow_id}'
    LIMIT 1
    """
    run_vql_query(vql, api_config_path)  # blocks until completed
    print("[+] Collection has completed.")


def fetch_collection_results(client_id, flow_id, api_config_path):
    """Fetches all results from a completed collection flow."""
    print(f"\n[📥] Fetching results for collection '{flow_id}'...")
    vql = f"""
    SELECT * FROM flow_results(client_id='{client_id}', flow_id='{flow_id}')
    """
    results = run_vql_query(vql, api_config_path)
    if results:
        print(f"[+] Successfully fetched {len(results)} result rows.")
    return results


def reduce_results(results):
    """Trim results to only important fields before sending to LLM."""
    trimmed = []
    
    for row in results:
        # Handle Windows.System.Pslist data
        if "Pid" in row and row.get("Pid"):
            proc = {
                "type": "running_process",
                "pid": row.get("Pid"),
                "name": row.get("Name"),
                "exe": row.get("Exe"),
                "command_line": row.get("CommandLine"),
                "ppid": row.get("PPid"),  # Parent process ID
                "create_time": row.get("CreateTime")
            }
            # Only add if we have meaningful data
            if proc["name"] or proc["exe"]:
                trimmed.append(proc)
        
        # Handle Windows.Forensics.Bam data
        elif "FullPath" in row and row.get("FullPath"):
            bam_entry = {
                "type": "bam_execution",
                "path": row.get("FullPath"),
                "last_execution": row.get("LastExecutionTime"),
                "sid": row.get("Sid")  # User SID who executed
            }
            trimmed.append(bam_entry)
            
        # Handle other potential artifacts
        elif "ProcessName" in row:  # Alternative process format
            proc = {
                "type": "process_activity",
                "name": row.get("ProcessName"),
                "path": row.get("ProcessPath"),
                "command_line": row.get("ProcessCommandLine")
            }
            if proc["name"]:
                trimmed.append(proc)
    
    # Limit results to avoid token limits (keep most suspicious looking first)
    if len(trimmed) > 150:
        print(f"[!] Trimming results from {len(trimmed)} to 100 entries")
        # Sort to prioritize suspicious-looking entries
        trimmed = sorted(trimmed, key=lambda x: is_potentially_suspicious(x), reverse=True)[:100]
    
    return trimmed


def is_potentially_suspicious(entry):
    """Simple heuristic to prioritize potentially suspicious entries."""
    suspicious_score = 0
    
    if entry["type"] == "running_process":
        exe = entry.get("exe", "").lower()
        name = entry.get("name", "").lower()
        cmd = entry.get("command_line", "").lower()
        
        # Suspicious locations
        if any(path in exe for path in ["/temp/", "/tmp/", "\\users\\", "\\appdata\\", "\\programdata\\"]):
            suspicious_score += 3
            
        # Suspicious names
        if any(sus in name for sus in ["powershell", "cmd", "wmic", "certutil", "bitsadmin"]):
            suspicious_score += 2
            
        # Suspicious command lines
        if any(sus in cmd for sus in ["-enc", "base64", "invoke", "downloadstring", "bypass"]):
            suspicious_score += 3
            
    elif entry["type"] == "bam_execution":
        path = entry.get("path", "").lower()
        
        # Suspicious execution paths
        if any(sus_path in path for sus_path in ["/temp/", "/tmp/", "\\users\\", "\\appdata\\"]):
            suspicious_score += 2
    
    return suspicious_score


def analyze_with_claude_bedrock(results):
    """Send trimmed results to Claude via AWS Bedrock for enhanced threat analysis."""
    
    try:
        client = boto3.client(
            "bedrock-runtime",
            region_name=BEDROCK_REGION,
            config=Config(read_timeout=BEDROCK_TIMEOUT)
        )
    except Exception as e:
        print(f"[!] Error creating Bedrock client: {e}")
        print("[!] Make sure AWS credentials are configured properly")
        return None

    results_str = json.dumps(results, indent=2)
    
    # Enhanced prompt for better threat detection
    prompt = f"""
You are a security analyst specializing in DFIR and threat hunting. Analyze the following Velociraptor artifact data for potential security threats. Focus first on identifying suspicious processes. Use these criteria for suspicion:
- Unusual parent-child relationships (e.g., lsass.exe not spawned by services.exe).
- Processes with no digital signature or from untrusted paths (e.g., not in System32).
- Known malicious process names or behaviors (e.g., rundll32.exe loading suspicious DLLs, or processes like cobaltstrike beacons).
- High resource usage, injection indicators, or command-line arguments suggesting evasion (e.g., obfuscated PowerShell).
- Connections to known bad IPs/domains or unusual network ports.

Artifact data:
[ARTIFACT_DATA]

Step 1: List all processes in the data and flag any that match the suspicious criteria above. Provide evidence from the data for each flagged process.
Step 2: If no suspicious processes are found, fallback to broader threat hunting: Scan for other indicators of compromise, such as anomalous files (e.g., recently modified in sensitive directories), unusual network connections (e.g., outbound to C2 servers), registry changes, or persistence mechanisms (e.g., scheduled tasks, autoruns).
Step 3: Summarize findings in a concise report, including risk level (low/medium/high), recommended actions (e.g., isolate endpoint, collect more artifacts), and any false positive explanations.

Output format:
- Suspicious Processes: [List with details or "None found"]
- Other Threats: [List with details or "None identified"]
- Summary: [Brief overview with PID if suspicious process found]
- Risk Level: [Low/Medium/High]
- Recommendations: [Bullet points]
- print in json pretty format, will send that alert to IRIS as case for further investigation.
{results_str}"""
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        "temperature": 0.3,  # Lower temperature for more focused analysis
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    }

    try:
        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json"
        )
        body = json.loads(response["body"].read())
        analysis_result = body["content"][0]["text"]
        
        print(f"[+] Claude analysis completed ({len(analysis_result)} characters)")
        return analysis_result
        
    except Exception as e:
        print(f"[!] Error invoking Claude via Bedrock: {e}")
        return None


# --- Wazuh Integration ---
def send_wazuh_alert(flow_id, llm_summary):
    """Sends the final, enriched alert to the Wazuh manager socket."""
    print(f"Sending enhanced alert to Wazuh for flow '{flow_id}'...")
    
    alert_payload = {
        "integration": "velociraptor-soar-enhanced",
        "velociraptor": { 
            "flow_id": flow_id, 
            "ai_analysis": llm_summary.strip(),
            "artifacts_collected": ARTIFACTS_TO_COLLECT,
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }
    }
    event_str = json.dumps(alert_payload)
    log_message = f'1:velociraptor-soar:{event_str}'

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET_ADDR)
        sock.send(log_message.encode())
        sock.close()
        print("[+] Successfully sent enhanced alert to Wazuh.")
    except Exception as e:
        print(f"[!] Error sending event to Wazuh socket: {e}")


# --- Scheduler ---
def graceful_exit(sig, frame):
    print(" Enhanced SOAR daemon stopped. Exiting cleanly...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Enhanced SOAR Workflow Runner with BAM Analysis")
    parser.add_argument(
        "-d", "--daemon",
        action="store_true",
        help="Run as a daemon (every 8 hours)"
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=8,
        help="Daemon interval in hours (default: 8)"
    )
    args = parser.parse_args()

    if args.daemon:
        # Handle Ctrl+C (SIGINT) gracefully
        signal.signal(signal.SIGINT, graceful_exit)
        signal.signal(signal.SIGTERM, graceful_exit)

        # Run as daemon
        schedule.every(args.interval).hours.do(run_soar_workflow)
        print(f" Enhanced SOAR daemon started. Workflow runs every {args.interval} hours...")
        print(f" Collecting artifacts: {', '.join(ARTIFACTS_TO_COLLECT)}")

        # Run once immediately, then on schedule
        print("Running initial workflow...")
        run_soar_workflow()

        while True:
            schedule.run_pending()
            time.sleep(60)  # check once per minute
    else:
        # Run once and exit
        run_soar_workflow()
        print("[✔] Enhanced SOAR workflow completed. Exiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()
