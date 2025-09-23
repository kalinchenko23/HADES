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
import docker
import time
import json
from pymetasploit3.msfrpc import MsfRpcClient

# Enhanced State class with better typing
class ReconState(TypedDict):
    ip: str
    user_input: str
    plan: str
    vulns: List[str]
    exploitation_attempt: bool
    shell_success: bool
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
    
def run_metasploit_auxiliary(target_ip: str, module_name: str, options: Dict[str, str] = None) -> str:
    """
    Run Metasploit auxiliary module
    Args:
        target_ip: Target IP address
        module_name: Metasploit auxiliary module name
        options: Additional options for the module
    """
    client = docker.from_env()

    try:
        container = client.containers.run('kali-metasploit:latest',
                                        detach=True, 
                                        remove=True,
                                        ports={'55552/tcp': 55552})
        time.sleep(15)  # Wait for msfrpcd to start
        
        msf_client = MsfRpcClient('password', host='localhost', port=55552)
        module = msf_client.modules.use('auxiliary', module_name)
        
        # Set target
        module['RHOSTS'] = target_ip
        
        # Set additional options
        if options:
            for key, value in options.items():
                module[key] = value
        
        result = module.execute()
        return f"Auxiliary scan completed: {str(result)}"
        
    except Exception as e:
        return f"Metasploit auxiliary failed: {str(e)}"
   
@tool
def run_metasploit_exploit(target_ip: str, module_name: str, payload: str, options: Dict[str, str] = None) -> str:
    """
    Run Metasploit exploit module
    Args:
        target_ip: Target IP address
        module_name: Metasploit exploit module name
        payload: Payload to use
        options: Additional options for the module
    """
    client = docker.from_env()
    
    try:
        container = client.containers.run('kali-metasploit',
                                        detach=True,                        
                                        remove=True,
                                        network_mode="host")
        time.sleep(15)
        
        msf_client = MsfRpcClient('password', host='localhost', port=55552)
        exploit = msf_client.modules.use('exploit', module_name)
        
        # Set target and payload
        exploit['RHOSTS'] = target_ip
        exploit['PAYLOAD'] = payload
        
        # Set additional options
        if options:
            for key, value in options.items():
                exploit[key] = value
        
        result = exploit.execute()
        
        # Check if we got a session
        sessions = msf_client.sessions.list
        if sessions:
            return f"Exploit successful! Sessions: {sessions}"
        else:
            return f"Exploit executed but no sessions created: {str(result)}"
        
    except Exception as e:
        return f"Metasploit exploit failed: {str(e)}"

# Create tool node
tools = [run_nmap_scan, run_metasploit_auxiliary, run_metasploit_exploit]
tool_node = ToolNode(tools)

# Planning Node
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
        ###THIS IS A SHORTCUT DUMMY OUTPUT REMOVE FOR PRODUCTION###
        state['scan_results']['Agressive scan'] = 'This is a Nmap scan output, which is a network scanning tool used to discover hosts, services, and operating systems on a network.\n\nHere are the key findings:\n\n**Open ports**\n\n* 21/tcp: FTP service running (vsftpd 2.3.4)\n* 22/tcp: SSH service running (OpenSSH 4.7p1 Debian 8ubuntu1)\n* 23/tcp: Telnet service running (Linux telnetd)\n* 25/tcp: SMTP service running (Postfix smtpd)\n* 53/tcp: DNS service running (ISC BIND 9.4.2)\n* 80/tcp: HTTP service running (Apache httpd 2.2.8)\n* 111/tcp: RPC service running\n* 139/tcp: NetBIOS service running (Samba smbd 3.X - 4.X)\n* 445/tcp: NetBIOS service running (Samba smbd 3.X - 4.X)\n* 512/tcp: Exec service running (netkit-rsh rexecd)\n* 513/tcp: Login service running (OpenBSD or Solaris rlogind)\n* 514/tcp: TCP-wrapped service\n* 1099/tcp: Java RMI service running\n* 1524/tcp: Bindshell service running (Metasploitable root shell)\n* 2049/tcp: NFS service running\n* 2121/tcp: FTP service running (ProFTPD 1.3.1)\n* 3128/tcp: Squid HTTP proxy service\n* 3306/tcp: MySQL database service running (MySQL 5.0.51a-3ubuntu5)\n* 5432/tcp: PostgreSQL database service running (PostgreSQL DB 8.3.0 - 8.3.7)\n* 5900/tcp: VNC service running\n\n**Operating System**\n\nThe operating system is likely a Linux distribution, possibly Ubuntu or Debian.\n\n**Vulnerabilities**\n\nThere are several potential vulnerabilities identified:\n\n* The FTP server allows anonymous login.\n* The SSH server uses an outdated version of OpenSSH (4.7p1).\n* The DNS server runs on an outdated version of BIND (9.4.2).\n* The HTTP server runs on an outdated version of Apache (2.2.8).\n\n**Other findings**\n\nThe Nmap scan also identified several other services running on the target host, including:\n\n* A Java RMI service\n* A bindshell service\n* An NFS service\n* A VNC service\n\nOverall, this report suggests that the target host has several potential vulnerabilities and outdated software installations.'
        print("Planning completed successfully")
        
    except Exception as e:
        error_msg = f"Planning failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['messages'].append(AIMessage(content=error_msg))
    
    return state

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

def determine_next_scan_type(state: ReconState, plan_content: str) -> tuple:
    """Determine the next scan type based on current state and plan"""
    scan_progression = state.get('scan_progression', [])
    discovered_services = state.get('discovered_services', {})
    scan_results = state.get('scan_results', {})
    
    # If no scans done yet, starts with fast discovery
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
    
    # CORRECTED PROMPT: This is now a template, not an f-string
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
        # CORRECTED INVOKE: Pass all variables for the template here
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
    """Assess vulnerabilities using Metasploit auxiliary modules"""
    print("Entering vuln_assessment_node")
    state['current_step'] = 'vulnerability_assessment'
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    llm_with_tools = llm.bind_tools(tools)
    
    system_prompt = """You are a vulnerability assessment specialist.
    Your task is to verify potential vulnerabilities based on the overall mission plan and the technical scan results.
    
    **Mission Plan:** {plan}
    
    Based on the plan's objectives and the open ports found, you MUST call the `run_metasploit_auxiliary` tool to investigate the most relevant services."""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Assess vulnerabilities for IP: {ip}\nScan results: {scan_results}"),
        MessagesPlaceholder(variable_name="messages")
    ])
    
    try:
        chain = prompt | llm_with_tools
        response = chain.invoke({
            "plan": state['plan'],
            "ip": state['ip'],
            "scan_results": state['scan_results'],
            "messages": []
        })
        
        state['messages'].append(response)
        print(response)
        # Execute tool calls if any
        if response.tool_calls:
            tool_results = tool_node.invoke({"messages": [response]})
            
            state['messages'].extend(tool_results['messages'])
            
            # Extract vulnerability information
            vulns = []
            for msg in tool_results['messages']:
                if hasattr(msg, 'content') and 'Auxiliary scan completed' in msg.content:
                    vulns.append(msg.content)
            
            state['vulns'] = vulns if vulns else ["No vulnerabilities assessed"]
        else:
            state['vulns'] = ["No vulnerability assessment performed"]
            
    except Exception as e:
        error_msg = f"Vulnerability assessment failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['vulns'] = [error_msg]
    
    return state

# Exploitation Node
def exploitation_node(state: ReconState) -> ReconState:
    """Attempt exploitation based on discovered vulnerabilities"""
    print("Entering exploitation_node")
    state['current_step'] = 'exploitation'
    state['exploitation_attempt'] = True
    state['shell_success'] = False
    
    if not state['vulns']:
        state['scan_results']['exploit'] = "No vulnerabilities to exploit"
        return state
    
    llm = get_llm(state['llm_provider'], state['api_key'], state['local_model'])
    llm_with_tools = llm.bind_tools(tools)
    
    system_prompt = """You are a penetration testing specialist.
    Your goal is to attempt exploitation according to the mission plan.
    
    **Mission Plan:** {plan}
    
    Review the plan and the discovered vulnerabilities. If the plan allows for it, you MUST call the `run_metasploit_exploit` tool to attempt an exploitation."""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Attempt exploitation for IP: {ip}\nVulnerabilities: {vulns}\n!"),
        MessagesPlaceholder(variable_name="messages")
    ])
    
    try:
        chain = prompt | llm_with_tools
        response = chain.invoke({
            "plan": state["plan"],
            "ip": state['ip'],
            "vulns": state['vulns'],
            "messages": []
        })
        print(response)
        state['messages'].append(response)
        
        # Execute tool calls if any
        if response.tool_calls:
            tool_results = tool_node.invoke({"messages": [response]})
            state['messages'].extend(tool_results['messages'])
            
            # Check for successful exploitation
            for msg in tool_results['messages']:
                if hasattr(msg, 'content'):
                    state['scan_results']['exploit'] = msg.content
                    if 'Exploit successful' in msg.content or 'Sessions:' in msg.content:
                        state['shell_success'] = True
        else:
            state['scan_results']['exploit'] = "No exploitation attempted"
            
    except Exception as e:
        error_msg = f"Exploitation failed: {str(e)}"
        print(error_msg)
        state['errors'].append(error_msg)
        state['scan_results']['exploit'] = error_msg
    
    return state

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
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("tools", tool_node)
    
    # Define the flow with conditional scanning
    workflow.set_entry_point("planning")
    # workflow.add_edge("planning", "scan")
    workflow.add_edge("planning", "vuln_assessment")
    # CONDITIONAL EDGE: Key change for Method 1
    # workflow.add_conditional_edges(
    #     "scan",
    #     should_continue_scanning,  # Decision function
    #     {
    #         "scan": "scan",                    # Loop back for more scanning
    #         "vuln_assessment": "vuln_assessment"  # Move to vulnerability assessment
    #     }
    # )
    
    workflow.add_edge("vuln_assessment", "exploitation")
    workflow.add_edge("exploitation", "analysis")
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

