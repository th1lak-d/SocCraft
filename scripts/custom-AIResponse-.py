----------> Used for AI(bedrock) gated response and remediation for the file dropped into the folder-------->


#!/var/ossec/framework/python/bin/python3
#!/usr/bin/env python
import sys
import json
import boto3
from socket import socket, AF_UNIX, SOCK_DGRAM

# --- Configuration ---
WAZUH_SOCKET_ADDR = '/var/ossec/queue/sockets/queue'
AWS_REGION = "eu-west-2"
BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"
EICAR_SHA256_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
LOG_FILE = "/var/ossec/logs/integrations.log"
def get_bedrock_insight(file_hash, hash_type, file_path, is_eicar):
    """Queries Amazon Bedrock for analysis and expects a JSON response."""
    eicar_instruction = ""
    if is_eicar:
        eicar_instruction = f"The provided {hash_type.upper()} hash matches the EICAR test file. You MUST set the 'is_eicar_test_file' boolean to true and the 'risk_level' to 'Medium'."

    prompt = f"""
As a senior malware analyst, you have received an alert for a file with the original path "{file_path}" and {hash_type.upper()} hash "{file_hash}".
Your response MUST be a single, valid JSON object and nothing else. Do not add any text before or after the JSON.
The JSON object must have the following keys:
- "threat_summary": (string) A concise summary of the threat.
- "follow strictly": if you see Eicar.com mark this as medium level risk, do not mark it informationl.
- "threat_actor": (string) Known associated threat actors, mapped to Mitre ATT&CK.
- "immediate_actions": (array of strings) A list of 3-5 remediation steps.
- "urgency": (string) A brief explanation of the urgency.
- "risk_level": (string) "Critical", "High", "Medium", "Low", or "Informational".
- "is_eicar_test_file": (boolean)
{eicar_instruction}
"""
    try:
        bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name=AWS_REGION)
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31", "max_tokens": 2048,
            "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
        })
        response = bedrock_runtime.invoke_model(body=body, modelId=BEDROCK_MODEL_ID)
        response_body = json.loads(response.get('body').read())
        # The AI's response text is itself a JSON string, so parsing it again
        ai_json_output = json.loads(response_body.get('content')[0].get('text'))
        return ai_json_output
    except Exception as e:
        return {"error": f"Bedrock analysis failed: {e}", "risk_level": "informational"}

def send_wazuh_alert(original_alert, ai_insight_json, file_hash, hash_type, file_path):
    """Sends the final, enriched alert to the Wazuh manager."""
    # Start with the AI's clean JSON response
    analysis_data = ai_insight_json.copy()

    # Add the critical context fields that Velociraptor might need
    analysis_data['file_path'] = file_path
    analysis_data['file_hash'] = file_hash
    analysis_data['hash_type'] = hash_type

    alert_payload = {
        "integration": "bedrock-hash-analyzer",
        "bedrock_analysis": analysis_data,
        "source_agent": original_alert.get("agent")
    }
    event_str = json.dumps(alert_payload)
    log_message = f'1:bedrock-analyzer:{event_str}'
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET_ADDR)
        sock.send(log_message.encode())
        sock.close()
        print(f"[+] Enriched alert for hash {file_hash} successfully sent to Wazuh.")
    except Exception as e:
        print(f"[!] Error sending event to Wazuh socket: {e}")

def extract_dynamic_hash(vt_data):
    """Dynamically searches for the best available hash in a prioritized order."""
    hash_priority = ["sha256", "sha1", "md5"]
    for hash_type in hash_priority:
        hash_value = vt_data.get(hash_type) or vt_data.get("source", {}).get(hash_type)
        if hash_value and isinstance(hash_value, str):
            return hash_value, hash_type
    return None, None

def main(alert_file_path):
    """Main function reads alert from a file path and processes it."""
    try:
        with open(alert_file_path, 'r', encoding='utf-8') as f:
            alert = json.load(f)
    except Exception as e:
        print(f"[!] Error reading alert file: {e}")
        return

    vt_data = alert.get("data", {}).get("virustotal", {})
    if not vt_data:
        return # Silently exit if not a VirusTotal alert

    file_hash, hash_type = extract_dynamic_hash(vt_data)
    file_path = vt_data.get("source", {}).get("file")

    if not file_path or not file_hash:
        return

    is_eicar_file = (hash_type == "sha256" and file_hash == EICAR_SHA256_HASH)

    print(f"[*] Active Response triggered for '{file_path}' with {hash_type.upper()} '{file_hash}'. Querying Bedrock...")
    ai_insight_json = get_bedrock_insight(file_hash, hash_type, file_path, is_eicar_file)

    if ai_insight_json and "error" not in ai_insight_json:
        send_wazuh_alert(alert, ai_insight_json, file_hash, hash_type, file_path)
    else:
        print(f"[!] Failed to get valid insight from Bedrock: {ai_insight_json.get('error')}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    main(sys.argv[1])
