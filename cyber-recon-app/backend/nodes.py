from typing import List, Dict, TypedDict, Optional, Annotated
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.prebuilt import ToolNode
from langgraph.graph.message import add_messages
from tools import get_llm, tools, tool_node, run_metasploit_exploit
import re

# State values for the langraph 
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
        
        # IMPORTANT: checking for the tool calls 
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
        messages = [
            ("system", system_prompt),
            ("human", f"Analyze these scan results and run vulnerability tests:\n\n{scan_summary}\n\nBased on the open services found, execute appropriate Metasploit auxiliary modules.")
        ]
        
        response = llm_with_tools.invoke(messages)
        state['messages'].append(response)
        
        # IMPORTANT: checking for the tool call
        if response.tool_calls:
            print(f"Executing {len(response.tool_calls)} vulnerability assessment tool calls")
            tool_results = tool_node.invoke({"messages": [response]})
            state['messages'].extend(tool_results['messages'])
            
            # Extract results
            results_content = ""
            for msg in tool_results['messages']:
                if hasattr(msg, 'content'):
                    results_content += f"{msg.content}\n"
            
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
    
    # Only bind exploit tools to prevent conflicts with auxilarry tool
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
    
    max_attempts = 7
    attempt_count = 0
    attempted_modules = set()  # Track what already has been tried
    
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
    Use the `interact_with_shell` tool to run commands.
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
