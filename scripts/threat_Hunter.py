--->Threat Hunter using FIASS disk and vector DB with RAG pipeline---------->


import json
import os
import gzip
import re
import uuid
import base64
import asyncio
import time
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
import httpx
import uvicorn
import argparse
import sys
import secrets
from contextlib import asynccontextmanager
from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, status, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain.schema import Document

# ==============================================================================
# Global Variables and Configuration
# ==============================================================================
vectorstores = {}
general_vectorstore = None
days_range = 7
min_alert_level = 7
model_name = "phi3:mini"
rule_info = {}

# Configuration
username = "admin"
password = "soccraft"
ssh_username = "your_ssh_user"
ssh_password = "your_ssh_password"
remote_host = None

# Enhanced Configuration
KEYWORD_EXTRACTION_TIMEOUT = 10  # seconds
ENABLE_FALLBACKS = True
MAX_DOCS_PER_SEARCH = 15

# ==============================================================================
# Application Startup and Shutdown Logic (Lifespan)
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print(" SOCCraft Threat Hunter AI initializing...")
    print("=" * 60)
    
    # Check Ollama connection
    try:
        async with httpx.AsyncClient() as client:
            await client.get("http://localhost:11434", timeout=5)
        print(" SOCCraft: Ollama AI engine connected")
    except httpx.RequestError:
        print(" SOCCraft: Ollama connection failed!")
        print("   Please ensure Ollama is running: `ollama serve`")
        print(f"   And the model is available: `ollama pull {model_name}`")
    
    # Initialize threat intelligence database
    await asyncio.to_thread(setup_vector_store, days_range)
    
    print(" SOCCraft: Security Operations Center ready!")
    print("=" * 60)
    
    yield
    
    # Code to run on shutdown
    print(" SOCCraft Threat Hunter shutting down.")


# ==============================================================================
# FastAPI App and Security Setup
# ==============================================================================
app = FastAPI(
    title="SOCCraft Threat Hunter",
    description="AI-Powered Threat Detection Platform",
    lifespan=lifespan
)
security = HTTPBasic()

# ==============================================================================
# Pydantic Models
# ==============================================================================
class Prompt(BaseModel):
    question: str

# ==============================================================================
# Enhanced UI with SOCCraft Branding and Peach Theme
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def get(request: Request):
    html_content = f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>SOCCraft Threat Hunter AI</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --peach-primary: #FF7F50;
                    --peach-light: #FFA07A;
                    --peach-dark: #CD5C34;
                    --peach-bg: #FFF8F0;
                    --dark-bg: #1a1a1a;
                    --dark-card: #2b2b2b;
                    --dark-input: #333;
                    --text-light: #e0e0e0;
                    --border-color: #444;
                }}
                
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{ 
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
                    background: linear-gradient(135deg, var(--dark-bg) 0%, #252525 100%);
                    color: var(--text-light); 
                    display: flex; 
                    flex-direction: column; 
                    height: 100vh;
                    overflow: hidden;
                }}
                
                /* Header */
                .header {{
                    background: linear-gradient(90deg, var(--peach-primary) 0%, var(--peach-light) 100%);
                    padding: 1rem 2rem;
                    color: white;
                    text-align: center;
                    box-shadow: 0 4px 20px rgba(255, 127, 80, 0.3);
                    position: relative;
                    overflow: hidden;
                }}
                
                .header::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.1'%3E%3Cpath d='m36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E") repeat;
                    opacity: 0.1;
                    z-index: 1;
                }}
                
                .header-content {{
                    position: relative;
                    z-index: 2;
                }}
                
                .header h1 {{
                    font-size: 2rem;
                    font-weight: 700;
                    margin-bottom: 0.5rem;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                }}
                
                .header .subtitle {{
                    font-size: 1rem;
                    font-weight: 400;
                    opacity: 0.9;
                }}
                
                .status-bar {{
                    background: rgba(255, 255, 255, 0.1);
                    padding: 0.5rem 1rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    font-size: 0.875rem;
                    border-top: 1px solid rgba(255, 255, 255, 0.2);
                }}
                
                /* Messages Area */
                #messages {{ 
                    flex-grow: 1; 
                    overflow-y: auto; 
                    padding: 1.5rem;
                    background: var(--dark-bg);
                    scrollbar-width: thin;
                    scrollbar-color: var(--peach-primary) var(--dark-bg);
                }}
                
                #messages::-webkit-scrollbar {{
                    width: 8px;
                }}
                
                #messages::-webkit-scrollbar-track {{
                    background: var(--dark-bg);
                }}
                
                #messages::-webkit-scrollbar-thumb {{
                    background: var(--peach-primary);
                    border-radius: 4px;
                }}
                
                .message {{ 
                    background: var(--dark-card);
                    padding: 1rem 1.25rem; 
                    border-radius: 16px; 
                    margin-bottom: 1rem; 
                    max-width: 85%; 
                    line-height: 1.6; 
                    word-wrap: break-word;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(255, 127, 80, 0.1);
                    transition: all 0.3s ease;
                }}
                
                .message:hover {{
                    border-color: rgba(255, 127, 80, 0.3);
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
                }}
                
                .message.user {{ 
                    background: linear-gradient(135deg, var(--peach-primary) 0%, var(--peach-light) 100%);
                    color: white; 
                    align-self: flex-end; 
                    margin-left: auto;
                    border: none;
                }}
                
                .message.bot {{ 
                    background: var(--dark-card);
                    align-self: flex-start;
                    position: relative;
                }}
                
                .message.bot::before {{
                    content: '(_)';
                    position: absolute;
                    top: -8px;
                    left: 12px;
                    background: var(--peach-primary);
                    width: 24px;
                    height: 24px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 12px;
                    box-shadow: 0 2px 8px rgba(255, 127, 80, 0.4);
                }}
                
                .message strong {{ color: var(--peach-light); }}
                .message code {{ 
                    background: rgba(255, 127, 80, 0.2); 
                    padding: 2px 6px; 
                    border-radius: 4px; 
                    color: var(--peach-light); 
                }}
                
                /* Typing indicator */
                .blinking-cursor {{ 
                    animation: blink 1s step-end infinite;
                    color: var(--peach-primary);
                    font-weight: bold;
                }}
                @keyframes blink {{ 50% {{ opacity: 0; }} }}
                
                /* Input Form */
                #form {{ 
                    display: flex; 
                    padding: 1.5rem; 
                    border-top: 1px solid var(--border-color);
                    background: linear-gradient(135deg, #252525 0%, var(--dark-card) 100%);
                    gap: 12px;
                }}
                
                #messageText {{ 
                    flex-grow: 1; 
                    padding: 14px 18px; 
                    border-radius: 24px; 
                    border: 2px solid var(--border-color);
                    background: var(--dark-input);
                    color: white; 
                    font-size: 16px;
                    font-family: inherit;
                    transition: all 0.3s ease;
                    outline: none;
                }}
                
                #messageText:focus {{
                    border-color: var(--peach-primary);
                    box-shadow: 0 0 0 4px rgba(255, 127, 80, 0.1);
                }}
                
                #messageText::placeholder {{
                    color: #888;
                }}
                
                button {{ 
                    background: linear-gradient(135deg, var(--peach-primary) 0%, var(--peach-dark) 100%);
                    color: white; 
                    padding: 14px 24px; 
                    border: none; 
                    border-radius: 24px; 
                    cursor: pointer; 
                    font-size: 16px;
                    font-weight: 600;
                    font-family: inherit;
                    transition: all 0.3s ease;
                    box-shadow: 0 4px 12px rgba(255, 127, 80, 0.3);
                }}
                
                button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(255, 127, 80, 0.4);
                }}
                
                button:active {{
                    transform: translateY(0);
                }}
                
                /* Login Overlay */
                #login-overlay {{ 
                    position: fixed; 
                    top: 0; 
                    left: 0; 
                    width: 100%; 
                    height: 100%; 
                    background: linear-gradient(135deg, rgba(26, 26, 26, 0.95) 0%, rgba(43, 43, 43, 0.95) 100%);
                    backdrop-filter: blur(10px);
                    display: flex; 
                    align-items: center; 
                    justify-content: center; 
                    z-index: 1000;
                }}
                
                #login-box {{ 
                    background: linear-gradient(135deg, var(--dark-card) 0%, #333 100%);
                    padding: 2.5rem; 
                    border-radius: 20px; 
                    text-align: center;
                    border: 2px solid var(--peach-primary);
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
                    min-width: 320px;
                }}
                
                #login-box h2 {{
                    color: var(--peach-primary);
                    margin-bottom: 1.5rem;
                    font-size: 1.75rem;
                    font-weight: 700;
                }}
                
                #login-box input {{
                    width: 100%;
                    padding: 12px 16px;
                    margin: 0.5rem 0;
                    border: 2px solid var(--border-color);
                    border-radius: 12px;
                    background: var(--dark-input);
                    color: white;
                    font-size: 16px;
                    font-family: inherit;
                    transition: all 0.3s ease;
                    outline: none;
                }}
                
                #login-box input:focus {{
                    border-color: var(--peach-primary);
                    box-shadow: 0 0 0 4px rgba(255, 127, 80, 0.1);
                }}
                
                #login-box button {{
                    width: 100%;
                    margin-top: 1rem;
                }}
                
                #login-error {{
                    color: #ff6b6b;
                    margin-top: 1rem;
                    font-size: 14px;
                }}
                
                /* Welcome Message Styling */
                .welcome-message {{
                    background: linear-gradient(135deg, var(--peach-primary) 0%, var(--peach-light) 100%);
                    color: white;
                    padding: 1.5rem;
                    border-radius: 16px;
                    margin: 1rem 0;
                    text-align: center;
                    box-shadow: 0 8px 24px rgba(255, 127, 80, 0.3);
                }}
                
                /* Responsive Design */
                @media (max-width: 768px) {{
                    .header h1 {{ font-size: 1.5rem; }}
                    .header .subtitle {{ font-size: 0.875rem; }}
                    #form {{ padding: 1rem; }}
                    .message {{ max-width: 95%; }}
                    #login-box {{ margin: 1rem; padding: 2rem; }}
                }}
            </style>
        </head>
        <body>
            <div id="login-overlay">
                <div id="login-box">
                    <h2> SOCCraft Login</h2>
                    <p style="color: #888; margin-bottom: 1.5rem;">Secure Access to Threat Intelligence</p>
                    <input type="text" id="username" placeholder="Username" value="admin">
                    <input type="password" id="password" placeholder="Password" autofocus onkeyup="if(event.key==='Enter'){{login()}}">
                    <button onclick="login()"> Launch SOCCraft</button>
                    <p id="login-error"></p>
                </div>
            </div>
            
            <div class="header">
                <div class="header-content">
                    <h1> SOCCraft Threat Hunter</h1>
                    <p class="subtitle">AI-Powered Security Operations Center</p>
                </div>
                <div class="status-bar">
                    <span> Model: <strong>{model_name}</strong></span>
                    <span> Alert Level: <strong>≥{min_alert_level}</strong></span>
                    <span> Range: <strong>{days_range} days</strong></span>
                </div>
            </div>
            
            <div id="messages"></div>
            
            <form id="form" onsubmit="sendMessage(event)">
                <input type="text" id="messageText" autocomplete="off" placeholder="🔍 Ask about threats, analyze patterns, or explore security events..."/>
                <button type="submit"> Analyze</button>
            </form>
            
            <script>
                let ws;
                let connectionRetries = 0;
                const maxRetries = 3;

                function login() {{
                    const user = document.getElementById('username').value;
                    const pass = document.getElementById('password').value;
                    
                    if (!user || !pass) {{
                        document.getElementById('login-error').textContent = 'Please enter both username and password';
                        return;
                    }}
                    
                    const token = btoa(`${{user}}:${{pass}}`);
                    const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
                    ws = new WebSocket(`${{wsProtocol}}://${{window.location.host}}/ws/chat?token=${{token}}`);
                    setupWebSocketHandlers();
                }}

                function setupWebSocketHandlers() {{
                    ws.onopen = () => {{ 
                        document.getElementById('login-overlay').style.display = 'none';
                        connectionRetries = 0;
                    }};
                    
                    ws.onclose = (event) => {{ 
                        if (connectionRetries < maxRetries && event.code !== 1008) {{
                            connectionRetries++;
                            setTimeout(() => {{
                                console.log(`Attempting to reconnect... (${{connectionRetries}}/${{maxRetries}})`);
                                login();
                            }}, 2000);
                        }} else {{
                            alert("🔌 Connection lost. Please refresh to reconnect.");
                            document.getElementById('login-overlay').style.display = 'flex';
                        }}
                    }};
                    
                    ws.onerror = (e) => {{ 
                        console.error("WebSocket error:", e);
                        document.getElementById('login-error').textContent = "Connection failed. Check your credentials.";
                    }};
                    
                    ws.onmessage = (event) => {{
                        const data = JSON.parse(event.data);
                        const messages = document.getElementById('messages');
                        let botMessage;

                        if (data.type === 'start_stream') {{
                            botMessage = document.createElement('div');
                            botMessage.id = data.id;
                            botMessage.classList.add('message', 'bot');
                            botMessage.innerHTML = '<span class="content"></span><span class="blinking-cursor">▍</span>';
                            messages.appendChild(botMessage);
                        }} else if (data.type === 'stream_chunk') {{
                            botMessage = document.getElementById(data.id);
                            if (botMessage) {{
                                const contentSpan = botMessage.querySelector('.content');
                                let currentContent = data.content.replace(/\\n/g, '<br>');
                                currentContent = formatContent(currentContent);
                                contentSpan.innerHTML += currentContent;
                            }}
                        }} else if (data.type === 'end_stream') {{
                            botMessage = document.getElementById(data.id);
                            if (botMessage) {{
                                const cursor = botMessage.querySelector('.blinking-cursor');
                                if (cursor) cursor.remove();
                            }}
                        }} else if (data.type === 'full_message') {{
                            const message = document.createElement('div');
                            message.classList.add('message', 'bot');
                            let html = data.content.replace(/\\n/g, '<br>');
                            html = formatContent(html);
                            message.innerHTML = html;
                            messages.appendChild(message);
                        }}
                        messages.scrollTop = messages.scrollHeight;
                    }};
                }}
                
                function formatContent(content) {{
                    return content
                        .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
                        .replace(/`([^`]+)`/g, '<code>$1</code>')
                        .replace(/🎯|📊|⚠️|✅|❌|🔍|🛡️|🚀|📅|⏱️|🤔|⚡/g, '<span style="color: var(--peach-light);">$&</span>');
                }}

                function sendMessage(event) {{
                    event.preventDefault();
                    const input = document.getElementById('messageText');
                    const message = input.value.trim();
                    
                    if (!message || !ws || ws.readyState !== WebSocket.OPEN) return;
                    
                    ws.send(message);
                    
                    const messages = document.getElementById('messages');
                    const messageDiv = document.createElement('div');
                    messageDiv.classList.add('message', 'user');
                    messageDiv.textContent = message;
                    messages.appendChild(messageDiv);
                    
                    input.value = '';
                    input.focus();
                    messages.scrollTop = messages.scrollHeight;
                }}
                
                // Auto-focus password input when page loads
                window.addEventListener('load', () => {{
                    document.getElementById('password').focus();
                }});
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ==============================================================================
# Enhanced Query Processing Class
# ==============================================================================
class SOCCraftQueryProcessor:
    def __init__(self, vectorstores, general_vectorstore, conversation, model_name="phi3:mini"):
        self.vectorstores = vectorstores
        self.general_vectorstore = general_vectorstore
        self.conversation = conversation
        self.model_name = model_name

    async def search_by_rule_id(self, rule_id: str, query: str) -> List[Document]:
        """
        Performs a high-precision search within a rule's dedicated vector store.
        """
        if rule_id not in self.vectorstores:
            return []

        print(f" RuleFound: Searching within dedicated index for Rule ID: {rule_id}")
        dedicated_db = self.vectorstores[rule_id]
        
        # Search within the small, dedicated DB. This is extremely fast and accurate.
        precise_docs = await asyncio.to_thread(dedicated_db.similarity_search, query, k=15)
        
        print(f" Found {len(precise_docs)} precise documents for Rule ID {rule_id}")
        return precise_docs

    async def intelligent_document_search(self, query: str) -> List[Document]:
        """
        Performs a general semantic search using the merged 'Top 10' vector store.
        """
        if not self.general_vectorstore:
            return []
        
        print(" --: Performing general semantic search...")
        relevant_docs = await asyncio.to_thread(self.general_vectorstore.similarity_search, query, k=15)
        return relevant_docs

    async def process_query_with_soccraft_intelligence(self, websocket, query: str) -> None:
        """Main SOCCraft query processing that decides which search strategy to use."""
        await websocket.send_json({
            "type": "full_message", 
            "content": " **SOCCraft Initializing**\n🔍 Analyzing query and hunting for relevant threat intelligence..."
        })
        
        rule_id_match = re.search(r'\b(\d{3,})\b', query)
        
        relevant_docs = []
        if rule_id_match and rule_id_match.group(1) in self.vectorstores:
            rule_id = rule_id_match.group(1)
            relevant_docs = await self.search_by_rule_id(rule_id, query)
        else:
            relevant_docs = await self.intelligent_document_search(query)

        if relevant_docs:
            await websocket.send_json({
                "type": "full_message",
                "content": f" **Analysis Ready**: Found {len(relevant_docs)} relevant security events\n **AI Processing**: Generating comprehensive threat analysis..."
            })
        else:
            await websocket.send_json({
                "type": "full_message",
                "content": "⚠️ **No Matches**: No relevant security logs were found for your query."
            })
        
        await handle_streaming_response(
            websocket, 
            self.conversation.generate_response_stream(query, relevant_docs)
        )

# ==============================================================================
# Authentication and Utility Functions
# ==============================================================================
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    """SOCCraft authentication system."""
    username_match = secrets.compare_digest(credentials.username, username)
    password_match = secrets.compare_digest(credentials.password, password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="SOCCraft: Unauthorized access attempt", 
            headers={"WWW-Authenticate": "Basic"}
        )
    return credentials.username

async def verify_websocket_auth(websocket: WebSocket) -> bool:
    """Verify SOCCraft WebSocket authentication."""
    try:
        auth_token = websocket.query_params.get("token")
        if not auth_token: return False
        decoded = base64.b64decode(auth_token).decode("utf-8")
        user_input, pwd_input = decoded.split(":", 1)
        user_match = secrets.compare_digest(user_input, username)
        pwd_match = secrets.compare_digest(pwd_input, password)
        return user_match and pwd_match
    except Exception:
        return False

def run_daemon():
    """Run SOCCraft as a system daemon."""
    try:
        import daemon
    except ImportError:
        print(" SOCCraft Error: 'python-daemon' library not found. Please run 'pip install python-daemon'.")
        sys.exit(1)
    log_file_path = "/var/ossec/logs/soccraft_threat_hunter.log"
    print(f" SOCCraft daemon mode starting. Logs: {log_file_path}")
    context = daemon.DaemonContext(
        stdout=open(log_file_path, 'a+'),
        stderr=open(log_file_path, 'a+')
    )
    with context:
        uvicorn.run(app, host="0.0.0.0", port=8000)

def load_logs_from_days(past_days=7):
    """Load security logs for SOCCraft analysis."""
    if remote_host:
        return load_logs_from_remote(remote_host, ssh_username, ssh_password, past_days)
    
    logs = []
    today = datetime.now()
    total_logs_scanned = 0
    print(f" SOCCraft: Loading logs from past {past_days} days with min alert level {min_alert_level}")
    
    for i in range(past_days):
        day = today - timedelta(days=i)
        year = day.year
        month_name = day.strftime("%b")
        day_num = day.strftime("%d")
        json_path = f"/var/ossec/logs/archives/{year}/{month_name}/ossec-archive-{day_num}.json"
        gz_path = f"{json_path}.gz"
        
        open_func, file_path = (gzip.open, gz_path) if os.path.exists(gz_path) else (open, json_path)
        if not os.path.exists(file_path):
            continue
            
        try:
            with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_logs_scanned += 1
                    if line.strip():
                        try:
                            log = json.loads(line)
                            if log.get("rule", {}).get("level", 0) >= min_alert_level:
                                logs.append(log)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"⚠️ SOCCraft: Error reading {file_path}: {e}")
    
    print(f" SOCCraft: Scanned {total_logs_scanned} logs, loaded {len(logs)} high-priority alerts")
    return logs

def load_logs_from_remote(host, user, password, past_days):
    """Load logs from remote host via SSH for SOCCraft."""
    try:
        import paramiko
    except ImportError:
        print(" SOCCraft Error: 'paramiko' library not found. Please run 'pip install paramiko' for SSH support.")
        return []
    
    logs = []
    print(f" SOCCraft: Connecting to remote host {host}")
    
    try:
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=user, password=password, timeout=30)
            print("⚠️ SOCCraft: Remote log loading is a placeholder and not fully implemented.")
    except Exception as e:
        print(f" SOCCraft: Remote connection failed: {e}")
    
    return logs

def extract_rule_info(logs):
    """Extract and analyze rule information for SOCCraft intelligence."""
    global rule_info
    rule_info_data = {}
    
    for log in logs:
        rule = log.get('rule', {})
        rule_id = str(rule.get('id', ''))
        if rule_id:
            if rule_id not in rule_info_data:
                rule_info_data[rule_id] = {
                    'description': rule.get('description', ''),
                    'level': rule.get('level', 0),
                    'groups': rule.get('groups', []),
                    'count': 0,
                    'timestamps': [],
                    'recent_activity': 0
                }
            rule_info_data[rule_id]['count'] += 1
            rule_info_data[rule_id]['timestamps'].append(log.get('timestamp', ''))
    
    yesterday = datetime.now() - timedelta(days=1)
    for rid, data in rule_info_data.items():
        data['timestamps'].sort(reverse=True)
        recent_count = 0
        for ts_str in data['timestamps']:
            try:
                # Handle timezone-aware parsing by making it naive
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None)
                if ts > yesterday:
                    recent_count += 1
            except (ValueError, TypeError):
                continue
        data['recent_activity'] = recent_count

    rule_info = rule_info_data
    print(f" SOCCraft: Analyzed {len(rule_info)} unique security rules")
    return rule_info

def flatten_dict(d: dict, parent_key: str = '', sep: str ='.') -> dict:
    """
    Flattens a nested dictionary.
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            if v is not None and isinstance(v, (str, int, float, bool)):
                items.append((new_key, v))
    return dict(items)

def format_log_for_embedding(log):
    """
    Dynamically formats logs for SOCCraft vector embedding by highlighting key data.
    """
    rule = log.get('rule', {})
    agent = log.get('agent', {})
    data = log.get('data', {})

    formatted_parts = [
        f"SOCCraft Security Alert - Rule {rule.get('id', 'Unknown')}",
        f"Description: {rule.get('description', 'No description')}",
        f"Severity Level: {rule.get('level', 0)}",
        f"Agent: {agent.get('name', 'Unknown')} ({agent.get('ip', 'Unknown IP')})",
        f"Groups: {', '.join(rule.get('groups', []))}",
    ]

    if data:
        flat_data = flatten_dict(data)
        high_value_keywords = ['command', 'path', 'user', 'ip', 'url', 'hash', 'name', 'query', 'file']
        key_data_highlights = []
        for key, value in flat_data.items():
            if any(keyword in key.lower() for keyword in high_value_keywords):
                display_key = key.replace('.', ' ').replace('_', ' ').title()
                key_data_highlights.append(f"Key Data ({display_key}): {value}")

        if key_data_highlights:
            formatted_parts.extend(key_data_highlights[:5])
    
    formatted_parts.append(f"Full Event: {log.get('full_log', 'No log data')}")
    formatted_parts.append(f"Timestamp: {log.get('timestamp', 'Unknown time')}")
    
    return "\n".join(formatted_parts)

def create_vectorstore(logs, embedding_model):
    """Create optimized FAISS vector store for SOCCraft."""
    documents = []
    for log in logs:
        metadata = {
            "rule_id": str(log.get("rule", {}).get("id", "")),
            "rule_description": log.get("rule", {}).get("description", ""),
            "rule_level": log.get("rule", {}).get("level", 0),
            "timestamp": log.get("timestamp", ""),
            "agent_name": log.get("agent", {}).get("name", ""),
            "agent_ip": log.get("agent", {}).get("ip", ""),
            "groups": ",".join(log.get("rule", {}).get("groups", []))
        }
        documents.append(Document(page_content=format_log_for_embedding(log), metadata=metadata))
    
    if not documents:
        return None
    return FAISS.from_documents(documents, embedding_model)

def setup_vector_store(past_days=7):
    """
    Creates dedicated vector stores for the Top 10 high-priority rules
    and a general store for broad queries.
    """
    global vectorstores, general_vectorstore, rule_info
    print(f" SOCCraft: Initializing threat intelligence database...")
    
    logs = load_logs_from_days(past_days)
    if not logs:
        print(" SOCCraft: No security logs found.")
        return False
    
    rule_info = extract_rule_info(logs)
    
    # Group logs by rule ID
    logs_by_rule = defaultdict(list)
    for log in logs:
        rule_id = log.get("rule", {}).get("id")
        if rule_id:
            logs_by_rule[str(rule_id)].append(log)
            
    # Identify Top 10 most frequent rules
    top_10_rules = sorted(logs_by_rule, key=lambda k: len(logs_by_rule[k]), reverse=True)[:10]
    print(f" Identified Top 10 rules for indexing: {top_10_rules}")
    
    embedding_model = HuggingFaceEmbeddings(
        model_name="BAAI/bge-small-en-v1.5", 
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True}
    )
    
    temp_vectorstores = {}
    all_top_10_docs = []

    for rule_id in top_10_rules:
        print(f" Creating dedicated index for Rule ID: {rule_id} ({len(logs_by_rule[rule_id])} alerts)...")
        rule_logs = logs_by_rule[rule_id]
        if rule_logs:
            # Create documents for this rule
            rule_docs = [
                Document(
                    page_content=format_log_for_embedding(log),
                    metadata={
                        "rule_id": str(log.get("rule", {}).get("id", "")),
                        "rule_description": log.get("rule", {}).get("description", ""),
                        "rule_level": log.get("rule", {}).get("level", 0),
                        "timestamp": log.get("timestamp", ""),
                        "agent_name": log.get("agent", {}).get("name", ""),
                        "agent_ip": log.get("agent", {}).get("ip", ""),
                        "groups": ",".join(log.get("rule", {}).get("groups", []))
                    }
                ) for log in rule_logs
            ]
            
            # Create the dedicated vector store for this rule
            db = FAISS.from_documents(rule_docs, embedding_model)
            temp_vectorstores[rule_id] = db
            
            # Add this rule's documents to our combined list
            all_top_10_docs.extend(rule_docs)

    # Create the general store from the combined list
    if all_top_10_docs:
        print(f" Creating general search index from {len(all_top_10_docs)} combined alerts...")
        general_vectorstore = FAISS.from_documents(all_top_10_docs, embedding_model)
        print(f" General index created with {general_vectorstore.index.ntotal} entries.")
    
    vectorstores = temp_vectorstores
    print(f" SOCCraft: Created {len(vectorstores)} dedicated threat intelligence databases.")
    return True

def initialize_assistant_context():
    """Initialize SOCCraft AI assistant's core persona and directives."""
    return """You are a specialized security log analysis engine for the SOCCraft platform.

**Core Directives:**
1. Your **ONLY** source of information is the user-provided security log data in the <CONTEXT> block.
2. **NEVER** mention that you are an AI, a large language model, or have a knowledge cutoff date. Your persona is that of an integrated analysis tool.
3. Answer questions **DIRECTLY** and **FACTUALLY** based *only* on the provided context.
4. If the context contains the specific information requested (like a command line, user, or IP), extract and present it directly.
5. If the context does not contain the answer, you MUST state: 'The provided logs do not contain the specific information required to answer the question.' Do not add any extra explanation or infer potential risks.
"""

# ==============================================================================
# Enhanced Streaming AI Logic for SOCCraft
# ==============================================================================
async def ollama_generate_stream(prompt, system, context):
    """Generate SOCCraft AI response with streaming."""
    payload = {
        "model": model_name, "prompt": prompt, "stream": True, "system": system, "context": context,
        "options": {"temperature": 0.1, "top_p": 0.9, "top_k": 40} 
    }
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            async with client.stream("POST", "http://localhost:11434/api/generate", json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        chunk = json.loads(line)
                        yield chunk
                        if chunk.get("done"):
                            yield {"final_context": chunk.get("context")}
    except httpx.RequestError as e:
        yield {"error": f"SOCCraft AI connection failed: {e}"}

class SOCCraftConversation:
    def __init__(self, system_prompt):
        self.system_prompt = system_prompt
        self.context = None
        
    async def generate_response_stream(self, query, relevant_docs=None):
        """Generate SOCCraft analysis with enhanced prompting."""
        if relevant_docs:
            context_str = "\n\n\n".join([f"Security Event {i+1}:\n{doc.page_content}" for i, doc in enumerate(relevant_docs[:8])])
        else:
            context_str = "No relevant security logs were found in the current dataset."
        
        prompt = f"""<TASK>
You are a log analysis engine. Your task is to analyze the security logs in the <CONTEXT> section below to answer the user's <QUERY>.
</TASK>

<INSTRUCTIONS>
- **CRITICAL:** Answer the user's <QUERY> using **ONLY** the data from the <CONTEXT> logs.
- **DO NOT** use any external knowledge or make assumptions.
- **DO NOT** apologize or mention you are an AI or have limitations.
- If the context contains the specific data (like a command line), state it directly.
- If the context does not contain the answer, you must respond with: 'The provided logs do not contain the specific information required to answer the question.'
</INSTRUCTIONS>

<CONTEXT>
{context_str}
</CONTEXT>

<QUERY>
{query}
</QUERY>

<ANALYSIS_RESPONSE>
"""

        async for chunk in ollama_generate_stream(prompt, self.system_prompt, self.context):
            if "final_context" in chunk:
                self.context = chunk["final_context"]
            else:
                yield chunk

async def handle_streaming_response(websocket, generator):
    """Enhanced streaming response handler for SOCCraft."""
    msg_id = str(uuid.uuid4())
    await websocket.send_json({"type": "start_stream", "id": msg_id})
    try:
        async for chunk in generator:
            if "error" in chunk:
                error_content = f"\n\n**SOCCraft Error:** {chunk['error']}"
                await websocket.send_json({"type": "stream_chunk", "id": msg_id, "content": error_content})
                break
            response_content = chunk.get("response", "")
            if response_content:
                await websocket.send_json({"type": "stream_chunk", "id": msg_id, "content": response_content})
    except Exception as e:
        error_content = f"\n\n**SOCCraft Error:** {str(e)}"
        await websocket.send_json({"type": "stream_chunk", "id": msg_id, "content": error_content})
    finally:
        await websocket.send_json({"type": "end_stream", "id": msg_id})

# ==============================================================================
# Query Processing and WebSocket Endpoint
# ==============================================================================
async def process_soccraft_query(websocket, data, conversation):
    """Process queries using SOCCraft's enhanced intelligence."""
    print(f" : Processing security query: {data}")
    processor = SOCCraftQueryProcessor(vectorstores, general_vectorstore, conversation, model_name)
    await processor.process_query_with_soccraft_intelligence(websocket, data)

async def summarize_rule_enhanced(websocket, rule_id, user_query=None):
    """Enhanced rule analysis for SOCCraft."""
    if rule_id not in rule_info:
        await websocket.send_json({"type": "full_message", "content": f" **SOCCraft**: Security rule `{rule_id}` not found in current dataset."})
        return
    
    rule = rule_info[rule_id]
    recent_activity = rule.get('recent_activity', 0)
    activity_indicator = "**" if recent_activity > 5 else "##" if recent_activity > 0 else "))"
    summary = f"""##  SOCCraft Rule Analysis: {rule_id}
**Rule Information:**
• **Description:** {rule['description']}
• **Severity Level:** {rule['level']}/15
• **Total Alerts:** {rule['count']:,}
• **Recent Activity (24h):** {recent_activity} alerts {activity_indicator}
• **Groups:** {', '.join(rule.get('groups', ['N/A']))}
**Latest Occurrences:**
{chr(10).join([f"• {ts}" for ts in rule['timestamps'][:3]])}
"""
    await websocket.send_json({"type": "full_message", "content": summary})
    
    if user_query and user_query.lower().strip() == f"/rule {rule_id}":
        analysis_prompt = (
            f"Provide a comprehensive threat assessment for Wazuh Rule {rule_id} ({rule['description']}) with severity {rule['level']}. "
            "Include threat classification, common attack vectors, potential impact, and recommended actions. "
            "Base this on general cybersecurity knowledge for this type of rule."
        )
        temp_conversation = SOCCraftConversation(initialize_assistant_context())
        await handle_streaming_response(websocket, temp_conversation.generate_response_stream(analysis_prompt))

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    global days_range, min_alert_level
    await websocket.accept()
    if not await verify_websocket_auth(websocket):
        await websocket.close(code=1008)
        return

    conversation = SOCCraftConversation(initialize_assistant_context())
    welcome_msg = f""" **Welcome to SOCCraft Threat Hunter**
*AI-Powered Security Operations Center*
** Current Configuration:**
• **AI Model:** `{model_name}`
• **Alert Threshold:** Level {min_alert_level}+ events
• **Time Range:** Last {days_range} days
• **Status:**  Active monitoring
** Quick Commands:**
• `/help` - View all commands
• `/stat` - Security overview dashboard
• `/top 10` - Most active security rules
• `/rule <id>` - Analyze specific rule
** Ask questions like:**
• "What SSH attacks were detected?"
• "Show me authentication failures"
• "Analyze rule 5712 in detail"
Ready to hunt threats! """
    await websocket.send_json({"type": "full_message", "content": welcome_msg})

    try:
        while True:
            data = (await websocket.receive_text()).strip()
            if not data: continue

            if data.lower().startswith("/"):
                await handle_command(websocket, data, conversation)
                continue
            
            try:
                await process_soccraft_query(websocket, data, conversation)
            except Exception as e:
                print(f" SOCCraft: Enhanced processing failed: {e}")
                await websocket.send_json({"type": "full_message", "content": "⚠️ **SOCCraft**: An error occurred during analysis."})

    except WebSocketDisconnect:
        print("⚠️ SOCCraft: Client disconnected from threat hunting session")
    except Exception as e:
        print(f" SOCCraft: WebSocket error: {e}")

async def handle_command(websocket, data, conversation):
    """Handle slash commands."""
    global days_range, min_alert_level
    command, *args = data.lower().split(maxsplit=1)
    arg_str = args[0] if args else ""
    
    if command == "/help":
        help_msg = """ **SOCCraft Command Center**
** Analysis Commands:**
• `/stat` - Security dashboard overview
• `/top <n>` - Top N active rules (default: 10)
• `/rule <id>` - Deep dive rule analysis (provides summary and general analysis)
**⚙️ Configuration Commands:**
• `/reload` - Refresh threat intelligence database
• `/set days <1-365>` - Set log analysis timeframe
• `/set level <1-15>` - Set minimum alert severity
• `/clear` - Reset conversation context
**💡 Pro Tips:**
• For specific details from a rule (like a command), ask a full question: "what command was executed in rule 100503?"
• Use `/rule <id>` for a general overview of a rule's purpose."""
        await websocket.send_json({"type": "full_message", "content": help_msg})
    
    elif command == "/reload":
        await websocket.send_json({"type": "full_message", "content": " **SOCCraft**: Reloading threat intelligence database..."})
        if await asyncio.to_thread(setup_vector_store, days_range):
            await websocket.send_json({"type": "full_message", "content": " **SOCCraft**: Database reloaded successfully."})
        else:
            await websocket.send_json({"type": "full_message", "content": " **SOCCraft**: Database reload failed. Check logs."})

    elif command == "/set":
        parts = arg_str.split()
        if len(parts) == 2 and parts[0] == "days" and parts[1].isdigit() and 1 <= int(parts[1]) <= 365:
            days_range = int(parts[1])
            await websocket.send_json({"type": "full_message", "content": f" **SOCCraft**: Time range set to **{days_range} days**. Use `/reload`."})
        elif len(parts) == 2 and parts[0] == "level" and parts[1].isdigit() and 1 <= int(parts[1]) <= 15:
            min_alert_level = int(parts[1])
            await websocket.send_json({"type": "full_message", "content": f" **SOCCraft**: Alert level set to **{min_alert_level}**. Use `/reload`."})
        else:
            await websocket.send_json({"type": "full_message", "content": "⚠️ **Usage**: `/set <days|level> <value>`"})

    elif command == "/stat":
        logs = await asyncio.to_thread(load_logs_from_days, days_range)
        stats_msg = get_stats(logs)
        await websocket.send_json({"type": "full_message", "content": stats_msg})

    elif command == "/clear":
        conversation.context = None
        await websocket.send_json({"type": "full_message", "content": " **SOCCraft**: Conversation context cleared."})

    elif command == "/rule":
        if not arg_str:
            await websocket.send_json({"type": "full_message", "content": "⚠️ **Usage**: `/rule <id>`"})
        else:
            await summarize_rule_enhanced(websocket, arg_str.strip(), user_query=data)
    
    elif command == "/top":
        n = int(arg_str) if arg_str.isdigit() else 10
        n = min(n, 25)
        if rule_info:
            sorted_rules = sorted(rule_info.items(), key=lambda item: item[1]['count'], reverse=True)[:n]
            top_msg = f" **SOCCraft Top {len(sorted_rules)} Most Active Rules**\n\n"
            for i, (rid, info) in enumerate(sorted_rules, 1):
                s_ind = "" if info['level'] >= 12 else "" if info['level'] >= 8 else ""
                r_ind = "" if info.get('recent_activity', 0) > 3 else ""
                top_msg += (f"{i}. **Rule {rid}** {s_ind} {r_ind}\n"
                            f"   • {info['description'][:80]}{'...' if len(info['description']) > 80 else ''}\n"
                            f"   • **{info['count']:,}** alerts | **Level {info['level']}** | Recent: {info.get('recent_activity', 0)}\n\n")
            await websocket.send_json({"type": "full_message", "content": top_msg})
        else:
            await websocket.send_json({"type": "full_message", "content": " No rule data available. Use `/reload`."})
    else:
        await websocket.send_json({"type": "full_message", "content": f"❓ Unknown command `{command}`. Type `/help`."})

# ==============================================================================
# Health Check and Main Entry Point
# ==============================================================================
@app.get("/health")
async def health_check():
    """SOCCraft health check endpoint."""
    status_data = {
        "service": "SOCCraft Threat Hunter", "status": "healthy", "ai_model": model_name,
        "vector_store": "online" if general_vectorstore else "offline", "alert_level": min_alert_level,
        "days_range": days_range, "rules_loaded": len(rule_info) if rule_info else 0
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.get("http://localhost:11434", timeout=3.0)
        status_data["ai_engine"] = "online"
    except httpx.RequestError:
        status_data["ai_engine"] = "offline"
        status_data["status"] = "degraded"
    return status_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOCCraft Threat Hunter - AI-Powered Security Operations Center",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python %(prog)s
  python %(prog)s -d
  python %(prog)s --days 14
  python %(prog)s -l 10 --days 30 -p 8080
  python %(prog)s -H 192.168.1.100
"""
    )
    parser.add_argument("-d", "--daemon", action="store_true", help="Run SOCCraft as a system daemon")
    parser.add_argument("-H", "--host", type=str, help="Remote host IP for log analysis")
    parser.add_argument("-l", "--level", type=int, default=7, help="Minimum alert level (1-15, default: 7)")
    parser.add_argument("--days", type=int, default=7, help="Days of logs to analyze (default: 7)")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Port to run SOCCraft on (default: 8000)")
    parser.add_argument("--model", type=str, default="phi3:mini", help="AI model to use (default: phi3:mini)")
    args = parser.parse_args()

    remote_host = args.host
    min_alert_level = args.level
    days_range = args.days
    model_name = args.model
    
    if args.daemon:
        print("🚀 SOCCraft: Launching in daemon mode...")
        run_daemon()
    else:
        print(f"🚀 SOCCraft: Starting interactive mode on port {args.port}")
        print(f"🌐 Access SOCCraft at: http://localhost:{args.port}")
        print("🛡️ Default credentials: admin / soccraft")
        try:
            uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")
        except KeyboardInterrupt:
            print("\n🛡️ SOCCraft: Threat hunting session terminated by user")
        except Exception as e:
            print(f"❌ SOCCraft: Failed to start - {e}")
            sys.exit(1)
