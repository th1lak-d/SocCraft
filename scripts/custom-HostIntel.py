#------>This scripts is used for Host intelligence using nmap----->

#!/var/ossec/framework/python/bin/python3
#!/usr/bin/env python
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

print(pwd)
#exit()

json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    debug("# API Key")
    debug(apikey)
    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Request OpenRouter info
    msg = request_openrouter_info(json_alert,apikey)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    f = open(log_file,"a")
    f.write(str(msg))
    f.close()


def collect(data):
  nmap_port_service = data['nmap_port_service']
  choices = data['content']
  return nmap_port_service, choices


def in_database(data, nmap_port_service):
  result = data['nmap_port_service']
  if result == 0:
    return False
  return True


def query_api(nmap_port_service, apikey):
  # === MODIFICATION FOR OPENROUTER START ===

  # Calling OpenRouter API Endpoint
  headers = {
        'Authorization': 'Bearer ' + apikey,
        'Content-Type': 'application/json',
        # Headers recommended by OpenRouter to identify your app
        'HTTP-Referer': 'https://wazuh.com', 
        'X-Title': 'Wazuh-Integration'
    }

  json_data = {
        # Model identifier chosen by the user
        'model': 'moonshotai/kimi-k2:free',
        'messages': [
            {
                'role': 'user',
                'content': 'In 4 or 5 sentences, tell me about this service and if there are past vulnerabilities: ' + nmap_port_service,
            },
        ],
    }

  # The URL is changed to the OpenRouter endpoint
  response = requests.post('https://openrouter.ai/api/v1/chat/completions', headers=headers, json=json_data)

  # === MODIFICATION FOR OPENROUTER END ===

  if response.status_code == 200:
      # Create new JSON to add the port service
      ip = {"nmap_port_service": nmap_port_service}
      new_json = {}
      # The response structure is compatible with OpenAI's
      new_json = response.json()["choices"][0]["message"]
      new_json.update(ip)
      json_response = new_json

      data = json_response
      return data
  else:
      alert_output = {}
      alert_output["openrouter"] = {}
      alert_output["integration"] = "custom-openrouter"
      json_response = response.json()
      debug("# Error: The OpenRouter API encountered an error")
      alert_output["openrouter"]["error"] = response.status_code
      alert_output["openrouter"]["description"] = json_response.get("error", {}).get("message", "Unknown error")
      send_event(alert_output)
      exit(0)


def request_openrouter_info(alert, apikey):
    alert_output = {}
    # If there is no port service present in the alert. Exit.
    if not "nmap_port_service" in alert["data"]:
        return(0)

    # Request info using OpenRouter API
    data = query_api(alert["data"]["nmap_port_service"], apikey)
    
    # Create alert
    alert_output["ai_analysis"] = {} # Renamed from "chatgpt" for clarity
    alert_output["integration"] = "custom-openrouter"
    alert_output["ai_analysis"]["found"] = 0
    alert_output["ai_analysis"]["source"] = {}
    alert_output["ai_analysis"]["source"]["alert_id"] = alert["id"]
    alert_output["ai_analysis"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["ai_analysis"]["source"]["description"] = alert["rule"]["description"]
    alert_output["ai_analysis"]["source"]["full_log"] = alert["full_log"]
    alert_output["ai_analysis"]["source"]["nmap_port_service"] = alert["data"]["nmap_port_service"]
    nmap_port_service = alert["data"]["nmap_port_service"]

    # Check if OpenRouter has any info about the nmap_port_service
    if in_database(data, nmap_port_service):
      alert_output["ai_analysis"]["found"] = 1
    
    # Info about the port service found
    if alert_output["ai_analysis"]["found"] == 1:
        nmap_port_service, choices = collect(data)

        # Populate JSON Output object with OpenRouter request
        alert_output["ai_analysis"]["nmap_port_service"] = nmap_port_service
        alert_output["ai_analysis"]["choices"] = choices

        debug(alert_output)

    return(alert_output)


def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        # Renamed 'chatgpt' to 'openrouter'
        string = '1:openrouter:{0}'.format(json.dumps(msg))
    else:
        # Renamed 'chatgpt' to 'openrouter'
        string = '1:[{0}] ({1}) {2}->openrouter:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(str(msg) + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
