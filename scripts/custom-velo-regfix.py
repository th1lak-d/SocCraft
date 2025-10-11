--->this scripts used for remediate the winlogon DLL persistence changinf the value to its known State---->

#!/var/ossec/framework/python/bin/python3
#!/usr/bin/env python

import json
import sys
import yaml
import grpc
import logging
import traceback
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

# --- Configuration ---
VELOCIRAPTOR_CONFIG = "/var/ossec/integrations/api.config.yaml"
WAZUH_SOCKET = '/var/ossec/queue/sockets/queue'
LOG_FILE = "/var/ossec/logs/integrations.log"

# --- Remediation Specifics ---
REG_PATH = "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
REG_NAME = "Userinit"
CORRECT_REG_VALUE = "Userinit.exe, C:\\Windows\\system32\\userinit.exe"

# --- Setup Logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_vql_query(vql, api_config_path):
    try:
        with open(api_config_path, "r") as f: config = yaml.safe_load(f)
        creds = grpc.ssl_channel_credentials(root_certificates=config["ca_certificate"].encode("utf8"), private_key=config["client_private_key"].encode("utf8"), certificate_chain=config["client_cert"].encode("utf8"))
        options = (('grpc.ssl_target_name_override', "VelociraptorServer"),)
        with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
            stub = api_pb2_grpc.APIStub(channel)
            request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
            all_responses = []
            for response in stub.Query(request):
                if response.Response: all_responses.extend(json.loads(response.Response))
            return all_responses
    except Exception as e:
        logging.error(f"VQL query failed: {e}")
        return None

def execute_powershell_command(client_id, command, description=""):
    """
    Executes a PowerShell command on a target client.
    --- THIS FUNCTION IS NOW FIXED ---
    """
    logging.info(f"Executing on {client_id}: {description}")

    # A simpler, more direct VQL query to start the collection
    vql = f"""
    LET collection = collect_client(
        client_id='{client_id}',
        artifacts=['Windows.System.PowerShell'],
        env=dict(Command={json.dumps(command)})
    )
    SELECT flow_id FROM collection
    """
    
    response = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    
    # A simpler, more robust check for the response
    if not response or 'flow_id' not in response[0]:
        logging.error(f"Failed to start PowerShell execution, no flow_id returned: {description}")
        return None
    
    # Simpler way to get the flow_id
    flow_id = response[0]['flow_id']
    logging.info(f"PowerShell execution started. Flow ID: {flow_id}")
    
    wait_vql = f"SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = '{flow_id}' LIMIT 1"
    run_vql_query(wait_vql, VELOCIRAPTOR_CONFIG)
    logging.info(f"Flow {flow_id} has completed.")
    
    results_vql = f"SELECT * FROM flow_results(client_id='{client_id}', flow_id='{flow_id}')"
    return run_vql_query(results_vql, VELOCIRAPTOR_CONFIG)

def reset_userinit_value(client_id):
    command = f"""$path = "{REG_PATH}"; $name = "{REG_NAME}"; $correctValue = "{CORRECT_REG_VALUE}"; try {{ Set-ItemProperty -Path $path -Name $name -Value $correctValue -Force -ErrorAction Stop; $newValue = (Get-ItemProperty -Path $path -Name $name).$name; if ($newValue -eq $correctValue) {{ Write-Output "SUCCESS: Userinit value has been reset to the default." }} else {{ Write-Output "ERROR: Attempted to set value, but verification failed. Current is '$newValue'." }} }} catch {{ Write-Output "ERROR: Failed to execute Set-ItemProperty. Details: $_" }}"""
    description = "Resetting Userinit value to default"
    results = execute_powershell_command(client_id, command, description)
    if results:
        for result in results:
            output = result.get("Stdout", "")
            if "SUCCESS:" in output: return True, output
            elif "ERROR:" in output: return False, output
    return False, "No valid response from PowerShell for Userinit reset."

def get_client_id_from_velociraptor(agent_name, agent_ip):
    logging.info(f"Searching for Velociraptor client for Wazuh agent: {agent_name} ({agent_ip})")
    vql = f"SELECT client_id FROM clients() WHERE os_info.hostname =~ '{agent_name}' OR last_ip = '{agent_ip}' ORDER BY last_seen_at DESC LIMIT 1"
    clients = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if not clients:
        logging.error(f"No Velociraptor clients found for {agent_name} ({agent_ip})")
        return None
    client_id = clients[0].get("client_id")
    logging.info(f"Found matching client ID: {client_id} for agent {agent_name}")
    return client_id

def send_wazuh_response(alert_id, action, target_path, success, details=""):
    try:
        if not isinstance(details, str): details = str(details)
        clean_details = details.encode('utf-8', 'ignore').decode('utf-8').strip()
        response_payload = {"integration": "velociraptor-userinit-ar", "alert_id": alert_id, "action_taken": action, "target_path": target_path, "success": success, "status": "success" if success else "failed", "details": clean_details, "timestamp": datetime.now().isoformat()}
        log_message = f'1:velociraptor-ar:{json.dumps(response_payload)}'
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET)
        sock.send(log_message.encode())
        sock.close()
        logging.info("Response successfully sent to Wazuh.")
    except Exception as e:
        logging.error(f"Failed to send response to Wazuh: {e}")

def main():
    try:
        if len(sys.argv) < 2: sys.exit(1)
        alert_file_path = sys.argv[1]
        with open(alert_file_path) as alert_file: alert = json.load(alert_file)
        logging.info(f"Processing alert: {alert.get('rule', {}).get('description', 'No description')}")
        agent_info = alert.get("agent", {})
        agent_name = agent_info.get("name", "unknown")
        agent_ip = agent_info.get("ip", "unknown")
        if agent_name == "unknown" and agent_ip == "unknown": sys.exit(1)
        target_path = f"{REG_PATH}\\{REG_NAME}"
        alert_id = alert.get("id", "unknown")
        client_id = get_client_id_from_velociraptor(agent_name, agent_ip)
        if not client_id:
            send_wazuh_response(alert_id, "FIND_CLIENT", f"{agent_name}/{agent_ip}", False, "Could not find Velociraptor client.")
            sys.exit(1)
        success, details = reset_userinit_value(client_id)
        send_wazuh_response(alert_id, "RESET_USERINIT", target_path, success, details)
        if not success: sys.exit(1)
    except Exception:
        logging.error("An unhandled error occurred in the integration script:\n%s", traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
