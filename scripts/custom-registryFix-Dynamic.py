-->used to fetch current logged in User ID (SID) and check Registry for the chnages and clear persistence off the endpoint--------------->

#!/var/ossec/framework/python/bin/python3
#!/usr/bin/env python

import json
import sys
import yaml
import grpc
import os
import logging
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

# Assuming pyvelociraptor is installed in the Wazuh Python environment
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

# --- Configuration ---
# Path to the Velociraptor API configuration file
VELOCIRAPTOR_CONFIG = "/var/ossec/integrations/api.config.yaml"
# Wazuh manager socket for sending feedback
WAZUH_SOCKET = '/var/ossec/queue/sockets/queue'
# Log file for this integration script
LOG_FILE = "/var/ossec/logs/integrations.log"
# The specific registry key this script is designed to remove
REGISTRY_PATH_TO_REMOVE = "SOFTWARE\\soccraft-test"
# The Wazuh rule ID that will trigger this active response
TRIGGER_RULE_ID = "100100" # IMPORTANT: Change this to your custom rule ID

# --- Setup Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_vql_query(vql, api_config_path):
    """Connects to the Velociraptor API and runs a VQL query."""
    try:
        with open(api_config_path, "r") as f:
            config = yaml.safe_load(f)
        
        creds = grpc.ssl_channel_credentials(
            root_certificates=config["ca_certificate"].encode("utf8"),
            private_key=config["client_private_key"].encode("utf8"),
            certificate_chain=config["client_cert"].encode("utf8")
        )
        options = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
        
        with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
            stub = api_pb2_grpc.APIStub(channel)
            request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
            all_responses = []
            for response in stub.Query(request):
                if response.Response:
                    all_responses.extend(json.loads(response.Response))
            return all_responses
    except Exception as e:
        logging.error(f"VQL query failed: {e}")
        return None

def execute_powershell_command(client_id, command, description=""):
    """
    Executes a PowerShell command on a target client using the core logic.
    This function launches the command, waits for it to complete, and returns the results.
    """
    logging.info(f"Executing on {client_id}: {description}")
    
    # VQL to launch the PowerShell artifact collection
    vql = f"""
    LET collection = collect_client(
        client_id='{client_id}',
        artifacts=['Windows.System.PowerShell'],
        env=dict(
            Command={json.dumps(command)}
        )
    )
    SELECT flow_id FROM collection
    """
    
    response = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if not response or "flow_id" not in response[0]:
        logging.error(f"Failed to start PowerShell execution: {description}")
        return None
    
    flow_id = response[0]["flow_id"]
    logging.info(f"PowerShell execution started. Flow ID: {flow_id}")
    
    # VQL to wait for the flow to complete
    wait_vql = f"""
    SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
    WHERE FlowId = '{flow_id}'
    LIMIT 1
    """
    run_vql_query(wait_vql, VELOCIRAPTOR_CONFIG)
    logging.info(f"Flow {flow_id} has completed.")
    
    # VQL to get the results of the completed flow
    results_vql = f"""
    SELECT * FROM flow_results(client_id='{client_id}', flow_id='{flow_id}')
    """
    results = run_vql_query(results_vql, VELOCIRAPTOR_CONFIG)
    
    return results

def remove_registry_key(client_id, reg_path_suffix):
    """
    Removes a registry key by finding the active user's session using a primary
    and a highly efficient fallback method for maximum reliability.
    """
    # This final version incorporates the user's elegant one-liner for the fallback,
    # making it the most robust and efficient solution.
    command = f"""
    $relativeKeyPath = '{reg_path_suffix}'
    $sidsToScan = @()

    # --- Primary Method: Check for explorer.exe ---
    # This remains the best primary method as it handles multiple logged-on users.
    $explorerProcesses = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'"
    if ($explorerProcesses) {{
        $sidsToScan = ($explorerProcesses | ForEach-Object {{ ($_.GetOwnerSid()).Sid }})
    }}

    # --- Fallback Method: Your elegant Win32_ComputerSystem one-liner ---
    # This runs if explorer.exe isn't found. It gets the logged-on user's
    # SID in a single, clean operation.
    if ($sidsToScan.Count -eq 0) {{
        try {{
            $userSid = (Get-CimInstance -ClassName Win32_ComputerSystem | 
                Select-Object @{{Name='Sid'; Expression={{([System.Security.Principal.NTAccount]$_.UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value}}}}).Sid
            
            if ($userSid) {{
                $sidsToScan = @($userSid)
            }}
        }} catch {{
            # This catch block handles cases where no user is logged on, or the username can't be translated.
            Write-Output "INFO: Fallback method could not determine logged on user."
        }}
    }}
    
    # --- Perform the Deletion ---
    if ($sidsToScan.Count -eq 0) {{
        Write-Output "INFO: No logged-on user could be found by any method."
        exit 0
    }}

    $keysFoundAndRemoved = 0
    foreach ($sid in $sidsToScan) {{
        # Filter out potential null or empty SIDs before processing
        if ($sid) {{
            $fullKeyPath = "Registry::HKEY_USERS\\$sid\\$relativeKeyPath"
            if (Test-Path $fullKeyPath) {{
                try {{
                    Remove-Item -Path $fullKeyPath -Recurse -Force -ErrorAction Stop
                    Write-Output "SUCCESS: Removed key for user SID $sid."
                    $keysFoundAndRemoved++
                }} catch {{
                    Write-Output "ERROR: Failed to remove key for SID $sid. Details: $_"
                }}
            }}
        }}
    }}

    if ($keysFoundAndRemoved -eq 0) {{
        Write-Output "INFO: Target key not found in any discovered user profile(s)."
    }}
    """
    
    description = f"Remove registry key for active user (definitive method): {reg_path_suffix}"
    results = execute_powershell_command(client_id, command, description)
    
    # The Python result-checking logic remains the same
    if results:
        for result in results:
            output = result.get("Stdout", "")
            if "SUCCESS:" in output:
                logging.info(f"Successfully removed registry key for active user on {client_id}")
                return True, "Successfully removed registry key for the active user."
            elif "ERROR:" in output:
                 logging.error(f"An error occurred during registry key removal: {output}")
                 return False, output
                 
        logging.info(f"Registry key not found for the active user on {client_id}.")
        return True, "Registry key did not exist for the active user."

    logging.error(f"No valid response from PowerShell for registry removal on {client_id}")
    return False, "No response from endpoint."

def get_client_id_from_velociraptor(agent_name, agent_ip):
    """Dynamically fetches the Velociraptor client ID based on the Wazuh agent name or IP."""
    logging.info(f"Searching for Velociraptor client for Wazuh agent: {agent_name} ({agent_ip})")
    
    vql = f"""
    SELECT client_id, os_info.hostname, last_ip
    FROM clients()
    WHERE os_info.hostname =~ '{agent_name}' OR last_ip = '{agent_ip}'
    ORDER BY last_seen_at DESC
    LIMIT 1
    """
    
    clients = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    
    if not clients:
        logging.error(f"No Velociraptor clients found for {agent_name} ({agent_ip})")
        return None
        
    client_id = clients[0].get("client_id")
    logging.info(f"Found matching client ID: {client_id} for agent {agent_name}")
    return client_id

def send_wazuh_response(alert, action, success, details):
    """Sends a response log back to the Wazuh manager's socket."""
    try:
        response_payload = {
            "integration": "velociraptor-registry-ar",
            "original_alert": {
                "id": alert.get("id"),
                "rule_id": alert.get("rule", {}).get("id"),
                "description": alert.get("rule", {}).get("description"),
                "agent_id": alert.get("agent", {}).get("id"),
                "agent_name": alert.get("agent", {}).get("name")
            },
            "action_taken": action,
            "target_path": REGISTRY_PATH_TO_REMOVE,
            "status": "success" if success else "failed",
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        
        # Wazuh log format: 1:integration-name:json_payload
        log_message = f'1:velociraptor-ar:{json.dumps(response_payload)}'
        
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET)
        sock.send(log_message.encode())
        sock.close()
        
        logging.info(f"Response sent to Wazuh: {log_message}")
    except Exception as e:
        logging.error(f"Failed to send response to Wazuh: {e}")

def main(args):
    """Main integration function."""
    try:
        if len(args) < 2:
            logging.error("Missing argument: alert file path.")
            sys.exit(1)
            
        alert_file_path = args[1]
        with open(alert_file_path) as alert_file:
            alert = json.load(alert_file)
        
        # --- Trigger Condition ---
        # Check if the alert is from the rule we want to act on
        rule_id = alert.get("rule", {}).get("id")
        if rule_id != TRIGGER_RULE_ID:
            logging.info(f"Skipping alert. Rule ID '{rule_id}' does not match trigger ID '{TRIGGER_RULE_ID}'.")
            sys.exit(0)
            
        logging.info(f"Processing alert for rule {rule_id}: {alert.get('rule', {}).get('description')}")
        
        # Get agent info to find the corresponding Velociraptor client
        agent_info = alert.get("agent", {})
        agent_name = agent_info.get("name", "unknown")
        agent_ip = agent_info.get("ip", "unknown")
        
        client_id = get_client_id_from_velociraptor(agent_name, agent_ip)
        if not client_id:
            send_wazuh_response(alert, "REMOVE_REGISTRY", False, f"Could not find Velociraptor client for agent {agent_name} ({agent_ip}).")
            sys.exit(1)
            
        # --- Execute Action ---
        success, details = remove_registry_key(client_id, REGISTRY_PATH_TO_REMOVE)
        
        # --- Send Feedback to Wazuh ---
        send_wazuh_response(alert, "REMOVE_REGISTRY", success, details)
        
        if success:
            logging.info(f"Active response completed successfully.")
            sys.exit(0)
        else:
            logging.error(f"Active response failed.")
            sys.exit(1)

    except Exception as e:
        logging.error(f"An unhandled error occurred in the integration script: {e}")
        # Send a failure response if a catastrophic error occurs
        try:
            # Create a minimal alert object for the response function if it failed early
            alert_data = {"id": "unknown", "rule": {"id": "unknown"}}
            send_wazuh_response(alert_data, "REMOVE_REGISTRY", False, f"Script error: {e}")
        except:
            pass # Avoid errors within the error handler
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
