
---># This script is designed to work with a local Ollama-compatible API.---->

#!/var/ossec/framework/python/bin/python3
# Wazuh Integration for Local LLM Enrichment

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# --- CONFIGURATION ---
# Set the name of the model you are using in Ollama
LOCAL_LLM_MODEL = "phi3:mini" # Change to "phi3:mini" or any other model you have
# Set the default Ollama API endpoint
LOCAL_LLM_ENDPOINT = "http://127.0.0.1:11434/api/chat"

# --- Global Vars ---
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f'{pwd}/logs/integrations.log'
socket_addr = f'{pwd}/queue/sockets/queue'

def main(args):
    """Main function to handle the integration execution."""
    debug("# Starting Local LLM Integration")
    alert_file_location = args[1]

    # Load the alert JSON
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug(f"# Processing alert: {json_alert.get('id')}")

    # Get LLM insights for the alert
    msg = request_local_llm_insight(json_alert)
    
    # If insights were generated, send them back to Wazuh
    if msg:
        send_event(msg, json_alert.get("agent"))

def debug(msg):
    """Writes a debug message to the integrations log."""
    if not debug_enabled:
        return
    
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    log_msg = f"{now}: custom-local-llm: {msg}\n"
    
    with open(log_file, "a") as f:
        f.write(log_msg)

def query_local_llm(prompt):
    """Sends a prompt to the local LLM and returns the response."""
    headers = {'Content-Type': 'application/json'}
    json_data = {
        'model': LOCAL_LLM_MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'stream': False
    }

    try:
        response = requests.post(LOCAL_LLM_ENDPOINT, headers=headers, json=json_data, timeout=120)
        
        if response.status_code == 200:
            response_json = response.json()
            # The actual message content is nested inside 'message' -> 'content'
            return response_json.get("message", {}).get("content", "No content found in response.")
        else:
            debug(f"# Error: Local LLM API returned status {response.status_code}")
            debug(f"# Response: {response.text}")
            return f"API Error: Status code {response.status_code}"

    except requests.exceptions.ConnectionError as e:
        debug("# Connection Error: Could not connect to the local LLM API.")
        debug(f"# Is your LLM service (e.g., Ollama) running and accessible at {LOCAL_LLM_ENDPOINT}?")
        debug(str(e))
        return "API Connection Error"
    except Exception as e:
        debug(f"# An unexpected error occurred in query_local_llm: {e}")
        return "An unexpected error occurred."

def request_local_llm_insight(alert):
    """Creates a prompt based on the alert rule and gets insights from the LLM."""
    rule_id = alert.get("rule", {}).get("id")
    full_log = alert.get("full_log", "No log available.")
    prompt = None

    # --- Rule-Specific Prompts ---
    # Add 'elif' blocks here for other rules you want to analyze.
    
    # Wazuh rule for "SSHD authentication failed."
    if rule_id == "5712": 
        prompt = f"""
        You are a senior security operations center (SOC) analyst.
        An SSH brute-force alert was triggered on a server. Analyze the following log and provide a brief, actionable summary for a system administrator.

        Log data:
        "{full_log}"

        Your response must include these three sections:
        1. Event Summary: Briefly explain what happened, including the source IP and target user if available.
        2. Immediate Actions: List the top 2-3 immediate steps the administrator should take to verify and contain the threat.
        3. Long-Term Hardening: Recommend 2-3 long-term security improvements to prevent future attacks of this nature.
        """

    # If no specific prompt was created for this rule ID, exit.
    if not prompt:
        debug(f"# Skipping alert with unhandled rule ID: {rule_id}")
        return None

    # Query the local LLM with the crafted prompt
    debug("# Querying local LLM...")
    llm_response = query_local_llm(prompt)

    # Create the new alert structure
    alert_output = {
        "integration": "custom-local-llm",
        "llm_insight": {
            "response": llm_response,
            "source": {
                "alert_id": alert.get("id"),
                "rule_id": rule_id,
                "description": alert.get("rule", {}).get("description"),
                "full_log": full_log
            }
        }
    }
    
    debug(f"# Generated new alert content: {alert_output}")
    return alert_output

def send_event(msg, agent=None):
    """Sends the new event to the Wazuh analysis engine via socket."""
    event_str = json.dumps(msg)
    
    if agent and agent.get("id") != "000":
        log = f'1:[{agent.get("id")}] ({agent.get("name", "any")}) {agent.get("ip", "any")}->local_llm:{event_str}'
    else:
        log = f'1:local_llm:{event_str}'
    
    debug(f"# Sending to analysisd: {log}")
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(log.encode())
        sock.close()
    except Exception as e:
        debug(f"# Error sending event to socket: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: <script_name> <alert_file_path> [debug]")
        sys.exit(1)
        
    # Enable debug mode if 'debug' is passed as an argument
    if len(sys.argv) > 2 and sys.argv[2] == 'debug':
        debug_enabled = True

    try:
        main(sys.argv)
    except Exception as e:
        debug(f"# Top-level error: {str(e)}")
