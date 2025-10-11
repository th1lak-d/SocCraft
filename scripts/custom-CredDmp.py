---------->this is used to collect the credential dump del from host and qurantine if neccessary usinng velociraptor-------->


#!/var/ossec/framework/python/bin/python3
#!/usr/bin/env python

import json
import sys
import os
import yaml
import grpc
import logging
import traceback
import time
from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

# --- Configuration ---
VELOCIRAPTOR_CONFIG = "/var/ossec/integrations/api.config.yaml"
WAZUH_SOCKET = '/var/ossec/queue/sockets/queue'
LOG_FILE = "/var/ossec/logs/integrations.log"
WAZUH_MANAGER_IP = "172.16.11.17"  # kept for reference if needed

# --- Wazuh Trigger Rule ---
TRIGGER_RULE_ID = "92026"

# --- Setup Logging ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_vql_query(vql, api_config_path):
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

def extract_and_build_path(alert):
    try:
        command_line = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine", "")
        current_dir = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("currentDirectory", "")

        if not command_line:
            logging.warning("Could not find 'commandLine' field in the alert.")
            return None

        parts = command_line.split()
        if len(parts) < 4:
            return None
        
        file_argument = parts[-1]

        if os.path.isabs(file_argument):
            logging.info(f"Extracted absolute file path: {file_argument}")
            return file_argument
        elif current_dir:
            full_path = os.path.join(current_dir, file_argument)
            logging.info(f"Extracted relative path '{file_argument}', built full path: {full_path}")
            return full_path
        else:
            logging.error(f"Extracted relative path '{file_argument}' but could not find currentDirectory in alert.")
            return None

    except Exception as e:
        logging.error(f"Could not parse alert to build file path: {e}")
    return None

def collect_quarantine_and_delete(client_id, file_path):
    vql_file_path = file_path.replace('\\', '/')

    # --- Step 1: COLLECT THE FILE ---
    logging.info(f"[{client_id}] Step 1: Collecting file {file_path}...")
    collect_vql = f"""LET flow = collect_client(client_id='{client_id}', artifacts=['Triage.Collection.Upload'], env=dict(path='{vql_file_path}', accessor='ntfs')) SELECT flow_id FROM flow"""
    collect_response = run_vql_query(collect_vql, VELOCIRAPTOR_CONFIG)
    if not collect_response or not collect_response[0].get('flow_id'):
        return False, f"Failed to start file collection for '{file_path}'."
    collect_flow_id = collect_response[0]['flow_id']
    logging.info(f"[{client_id}] Collection started (Flow: {collect_flow_id}). Waiting for completion...")
    wait_vql = f"SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = '{collect_flow_id}' LIMIT 1"
    run_vql_query(wait_vql, VELOCIRAPTOR_CONFIG)
    logging.info(f"[{client_id}] File collection completed.")
    time.sleep(1)

    # --- Step 2: DELETE THE FILE ---
    logging.info(f"[{client_id}] Step 2: Deleting original file {file_path}...")
    delete_vql = f"""LET flow = collect_client(client_id='{client_id}', artifacts=['Windows.Remediation.Glob'], env=dict(TargetGlob='{vql_file_path}', NoDir=true, ReallyDoIt=true)) SELECT flow_id FROM flow"""
    delete_response = run_vql_query(delete_vql, VELOCIRAPTOR_CONFIG)
    if not delete_response or not delete_response[0].get('flow_id'):
        return False, f"File collected, but FAILED to start file deletion."
    delete_flow_id = delete_response[0]['flow_id']
    logging.info(f"[{client_id}] File deletion initiated (Flow: {delete_flow_id}).")
    time.sleep(5)

    # --- Step 3: QUARANTINE THE HOST ---
    logging.info(f"[{client_id}] Step 3: Quarantining host with custom artifact...")
    quarantine_vql = f"""
        LET flow = collect_client(
            client_id='{client_id}',
            artifacts=['Custom.Windows.Remediation.Quarantine'],
            env=dict(
                MessageBox='CRITICAL SECURITY ALERT: This machine has been quarantined due to credential theft activity. Please do not restart or shut down. Contact IT Security immediately.'
            )
        )
        SELECT flow_id FROM flow
    """
    quarantine_response = run_vql_query(quarantine_vql, VELOCIRAPTOR_CONFIG)
    if not quarantine_response or not quarantine_response[0].get('flow_id'):
        return False, f"File collected and deleted, but FAILED to start quarantine."
    quarantine_flow_id = quarantine_response[0]['flow_id']
    logging.info(f"[{client_id}] Host quarantine initiated (Flow: {quarantine_flow_id}). Waiting for completion...")
    wait_quarantine = f"SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = '{quarantine_flow_id}' LIMIT 1"
    run_vql_query(wait_quarantine, VELOCIRAPTOR_CONFIG)
    logging.info(f"[{client_id}] Quarantine flow completed.")

    details = f"SUCCESS. Collected '{file_path}' (Flow: {collect_flow_id}). Original file deleted (Flow: {delete_flow_id}). Host quarantined (Flow: {quarantine_flow_id})."
    return True, details

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

def send_wazuh_response(alert_id, action, target_agent_name, success, details=""):
    try:
        if not isinstance(details, str): 
            details = str(details)
        clean_details = details.encode('utf-8', 'ignore').decode('utf-8').strip()
        response_payload = {
            "integration": "velociraptor-samdump-ar",
            "alert_id": alert_id,
            "action_taken": action,
            "target_agent": target_agent_name,
            "status": "success" if success else "failed",
            "details": clean_details,
            "timestamp": datetime.now().isoformat()
        }
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
        alert_file_path = sys.argv[1]
        with open(alert_file_path) as alert_file:
            alert = json.load(alert_file)
        if alert.get("rule", {}).get("id") != TRIGGER_RULE_ID:
            sys.exit(0)
        
        logging.info(f"Processing SAM dump alert: {alert.get('rule', {}).get('description')}")
        
        dumped_file = extract_and_build_path(alert)
        if not dumped_file:
            send_wazuh_response(alert.get("id"), "COLLECT_DELETE_QUARANTINE", alert.get("agent", {}).get("name"), False, "Could not build full file path from alert.")
            sys.exit(1)

        agent_info = alert.get("agent", {})
        agent_name = agent_info.get("name", "unknown")
        agent_ip = agent_info.get("ip", "unknown")
        alert_id = alert.get("id", "unknown")

        client_id = get_client_id_from_velociraptor(agent_name, agent_ip)
        if not client_id:
            send_wazuh_response(alert_id, "COLLECT_DELETE_QUARANTINE", agent_name, False, "Could not find Velociraptor client.")
            sys.exit(1)
            
        success, details = collect_quarantine_and_delete(client_id, dumped_file)
        
        send_wazuh_response(alert_id, "COLLECT_DELETE_QUARANTINE", agent_name, success, details)
        
        if not success:
            sys.exit(1)

    except Exception:
        logging.error("An unhandled error occurred in the integration script:\n%s", traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
