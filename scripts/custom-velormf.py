----->Script is used to Del, Qurantine, or Monitor the malware as per the AI recommdations-------->

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
QUARANTINE_DIR = r"C:\Quarantine"
WAZUH_SOCKET = '/var/ossec/queue/sockets/queue'
LOG_FILE = "/var/ossec/logs/integrations.log"

# --- Setup Logging ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def extract_info_from_ai_alert(alert):
    logging.info("Extracting information from AI alert...")
    file_path, risk_level = None, "info"
    ai_data = alert.get("data", {}).get("bedrock_analysis", {})
    file_path = ai_data.get("file_path")
    if file_path:
        file_path = file_path.replace("/", "\\").strip()
    risk_level = ai_data.get("risk_level", "info").lower().strip()
    logging.info(f"Extracted: File='{file_path}', Risk='{risk_level}'")
    return file_path, risk_level

def get_client_id_from_velociraptor(agent_name, agent_ip):
    logging.info(f"Looking up Velociraptor client for agent: {agent_name} ({agent_ip})")
    vql = f"SELECT client_id FROM clients() WHERE os_info.hostname =~ '{agent_name}' OR last_ip = '{agent_ip}' ORDER BY last_seen_at DESC LIMIT 1"
    clients = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if not clients:
        logging.error(f"No Velociraptor clients found for {agent_name} ({agent_ip})")
        return None
    client_id = clients[0].get("client_id")
    logging.info(f"Selected client ID: {client_id} for agent {agent_name}")
    return client_id

def send_wazuh_response(alert, action, file_path, success, details=""):
    try:
        if not isinstance(details, str): details = str(details)
        clean_details = details.encode('utf-8', 'ignore').decode('utf-8').strip()
        payload = {"integration": "velociraptor-ai-ar", "original_alert": { "id": alert.get("id"), "rule_id": alert.get("rule", {}).get("id") }, "action_taken": action, "target_file": file_path, "status": "success" if success else "failed", "details": clean_details, "timestamp": datetime.now().isoformat()}
        msg = f'1:velociraptor-ar:{json.dumps(payload)}'
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(WAZUH_SOCKET)
            sock.send(msg.encode())
        logging.info(f"Response sent to Wazuh: {action} for {file_path}")
    except Exception as e:
        logging.error(f"Failed to send response to Wazuh: {e}")

# --- Remediation Actions (Simplified for POC) ---
def upload_file(client_id, file_path):
    logging.info(f"Uploading {file_path} from {client_id}")
    vql_file_path = file_path.replace('\\', '/')
    vql = f"""LET flow = collect_client(client_id='{client_id}', artifacts=['Triage.Collection.Upload'], env=dict(path='{vql_file_path}', accessor='ntfs')) SELECT flow_id FROM flow"""
    results = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if results and results[0].get('flow_id'):
        flow_id = results[0]['flow_id']
        logging.info(f"Upload flow started successfully ({flow_id}).")
        return True, f"File upload initiated. Flow ID: {flow_id}"
    else:
        return False, "Upload failed to start"

def delete_file(client_id, file_path):
    logging.info(f"Deleting file {file_path} on {client_id}")
    vql_file_path = file_path.replace('\\', '/')
    vql = f"""LET flow = collect_client(client_id='{client_id}', artifacts=['Windows.Remediation.Glob'], env=dict(TargetGlob='{vql_file_path}', NoDir=true, ReallyDoIt=true)) SELECT flow_id FROM flow"""
    results = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if results and results[0].get('flow_id'):
        flow_id = results[0]['flow_id']
        logging.info(f"File deletion started successfully ({flow_id}).")
        return True, f"File deletion initiated. Flow ID: {flow_id}"
    else:
        return False, "Delete failed to start"

def quarantine_file(client_id, file_path):
    logging.info(f"[{client_id}] Launching custom quarantine artifact for {file_path}")
    vql_source_path = file_path.replace('\\', '\\\\')
    vql_dest_path = QUARANTINE_DIR.replace('\\', '\\\\')
    vql = f"""
        LET quarantine_flow = collect_client(
            client_id='{client_id}',
            artifacts=['Custom.Utils.MoveFile'],
            env=dict(
                sourcePath='{vql_source_path}',
                destinationPath='{vql_dest_path}'
            )
        )
        SELECT flow_id FROM quarantine_flow
    """
    results = run_vql_query(vql, VELOCIRAPTOR_CONFIG)
    if results and results[0].get('flow_id'):
        flow_id = results[0]['flow_id']
        logging.info(f"Quarantine flow started successfully ({flow_id}).")
        return True, f"File quarantine initiated. Flow ID: {flow_id}"
    else:
        return False, "Failed to launch Custom.Utils.MoveFile artifact."

def determine_action_from_ai(risk_level):
    risk_level = risk_level.lower().strip()
    if risk_level in ["critical", "high"]: return "DELETE"
    elif risk_level == "medium": return "QUARANTINE"
    else: return "MONITOR"

def main(args):
    try:
        alert_file_path = args[1]
        with open(alert_file_path, 'r', encoding='utf-8') as alert_file:
            alert = json.load(alert_file)

        logging.info(f"Processing alert: {alert.get('rule', {}).get('description')}")

        file_path, risk_level = extract_info_from_ai_alert(alert)
        if not file_path:
            send_wazuh_response(alert, "FAILED", "N/A", False, "No file path found in alert")
            sys.exit(0)

        action = determine_action_from_ai(risk_level)
        logging.info(f"Determined action: {action} for file {file_path} with risk level: {risk_level}")

        source_agent = alert.get("data", {}).get("source_agent", {})
        agent_name = source_agent.get("name", "")
        agent_ip = source_agent.get("ip", "")
        if not agent_name and not agent_ip:
            logging.warning("No source_agent found, falling back to agent field.")
            agent = alert.get("agent", {})
            agent_name = agent.get("name", "")
            agent_ip = agent.get("ip", "")

        client_id = get_client_id_from_velociraptor(agent_name, agent_ip)
        if not client_id:
            send_wazuh_response(alert, "FAILED", file_path, False, "No Velociraptor client found")
            sys.exit(1)

        success, details = False, ""
        if action == "DELETE":
            upload_success, upload_details = upload_file(client_id, file_path)
            # We don't wait, but we still report both actions were attempted
            success, details = delete_file(client_id, file_path)
            details = f"Upload: {upload_details}. Deletion: {details}"

        elif action == "QUARANTINE":
            upload_success, upload_details = upload_file(client_id, file_path)
            success, details = quarantine_file(client_id, file_path)
            details = f"Upload: {upload_details}. Quarantine: {details}"

        else: # MONITOR
            success, details = True, "File marked for monitoring only"

        send_wazuh_response(alert, action, file_path, success, details)

        if not success:
            sys.exit(1)

    except Exception:
        logging.error("An unhandled error occurred in the integration script:\n%s", traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
