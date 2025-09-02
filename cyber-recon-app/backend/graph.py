from typing import TypedDict, Annotated, List, Dict
from langchain_openai import OpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
import autogen
import docker
import time
import nmap
from pymetasploit3.msfrpc import MsfRpcClient
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama

#State class that will be accessed and modified by nodes 
class ReconState(TypedDict):
    ip: str
    user_input: str
    scan_results: Dict[str, str] # e.g., {"nmap": "ports open: 22,80"}
    vulns: List[str] # List of detected vulnerabilities
    exploitation_attempt: bool # Did we try to get a shell?
    shell_success: bool # Did shell succeed?
    report: str  # Final report
    llm_provider: str
    api_key: str
    local_model: str 
    messages: Annotated[list, add_messages] # AutoGen chat history


# Function that chooses model based on the provider
def choose_llm(llm_provider,api_key,local_model):
    if llm_provider=="ollama":
        return [{"model": local_model, "base_url": "http://localhost:11434/v1", "api_key": "NULL"}]
    elif llm_provider=="":
        return [{"model": "GPT-4 mini", "api_key": api_key}]
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider}")

# AutoGen planning node
def planning_node(state: ReconState) -> ReconState:
    config_list = choose_llm(state['llm_provider'],state['api_key'],state['local_model'])       
    # Initializing planner
    planner = autogen.AssistantAgent(
        name="Planner", 
        llm_config={"config_list": config_list},
        system_message="Plan reconnaissance steps for the given IP.")
    
    # Initializing ethics 
    ethics = autogen.AssistantAgent(
        name="EthicsChecker",
        llm_config={"config_list": config_list},
        system_message="Ensure actions are authorized and ethical. Confirm consent."
    )
    # Initializing user proxy 
    user_proxy = autogen.UserProxyAgent(name="UserProxy", human_input_mode="NEVER")

    # Starting groupchat between agents 
    groupchat = autogen.GroupChat(agents=[planner, ethics, user_proxy], messages=[])

    # Initializing groupchat manager
    manager = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})
    
    # Initiating chat
    manager.initiate_chat(user_proxy, message=f"Plan recon for IP {state['ip']}. Confirm authorization.")

    state['messages'] = groupchat.messages
    state['scan_results'] = {}

    return state

# Helper function for Scan node
def run_nmap_command(container, command):
    exec_result = container.exec_run(command)
    output = exec_result.output.decode('utf-8')
    return output

# AutoGen NMAP scanning node
def scan_node(state: ReconState) -> ReconState:
    config_list = choose_llm(state)
    client = docker.from_env()
    container = client.containers.run('kalilinux/kali-rolling', detach=True, command='sleep infinity')
    try:
        # This agent decide on what type of scan should be excecuted 
        scan_decider = autogen.AssistantAgent(
            name="ScanDecider",
            llm_config={"config_list": config_list},
            system_message="Decide on appropriate scanning commands based on the plan and IP. Suggest nmap options like port ranges, scan types (e.g., -sV for version, -O for OS detection), or other tools if available. Ensure commands are ethical and targeted."
        )
        # This is an ethics agent
        ethics = autogen.AssistantAgent(
            name="EthicsChecker",
            llm_config={"config_list": config_list},
            system_message="Review and approve scan commands for ethical compliance."
        )
        user_proxy = autogen.UserProxyAgent(
            name="UserProxy",
            human_input_mode="NEVER",
            code_execution_config=False,
            default_auto_reply="",
            is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE")
        )
        # Define tool for executing in container
        user_proxy.register_function(
            function_map={
                "run_nmap_command": lambda command: run_nmap_command(container, command)
            }
        )

        groupchat = autogen.GroupChat(agents=[scan_decider, ethics, user_proxy], messages=[])
        manager = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})
        manager.initiate_chat(
            user_proxy,
            message=f"Decide and execute scan for IP {state['ip']}. Previous plan: {state['messages'][-1]['content'] if state['messages'] else 'No plan available.'}"
        )
        # Extract executed command output from chat history
        executed_output = [msg['content'] for msg in groupchat.messages if 'tool_calls' in msg or 'function_call' in msg]  # Parse tool calls for output
        state['scan_results']['nmap'] = executed_output[-1] if executed_output else "No scan output."
        state['messages'].extend(groupchat.messages)
    except Exception as e:
        state['scan_results'] = [f"Error: {str(e)}"]
    finally:
        container.remove(force=True)
    return state

# Helper function for Vulnarability assessment node 
def run_metasploit_command(msf_client, module_type, module_name, options):
    if module_type == 'auxiliary':
        module = msf_client.modules.use('auxiliary', module_name)
    elif module_type == 'exploit':
        module = msf_client.modules.use('exploit', module_name)
    else:
        return "Invalid module type."
    for key, value in options.items():
        module[key] = value
    result = module.execute()
    return str(result)

# AutoGen vulnarability assesment node
def vuln_assessment_node(state: ReconState) -> ReconState:
    # Creating container with port binding so that msfclient will be able to use it
    client = docker.from_env()
    container = client.containers.run('kali-metasploit', detach=True, ports={'55552/tcp': 55552})
    try: 
        time.sleep(5) # Wait for msfrpcd
        msf_client = MsfRpcClient('password', host='localhost', port=55552)
        config_list = choose_llm(state)

        # This agent decide what auxiliary modules or scans should be used to assess vulnerabilities
        vuln_decider = autogen.AssistantAgent(
            name="VulnDecider",
            llm_config={"config_list": config_list},
            system_message="Based on scan results, decide on Metasploit auxiliary modules or scans to assess vulnerabilities. Suggest modules like scanner/http/http_version or db_nmap integration. Provide module type, name, and options dictionary."
        )

        # This is an ethics agent
        ethics = autogen.AssistantAgent(
            name="EthicsChecker",
            llm_config={"config_list": config_list},
            system_message="Review and approve vuln assessment commands for ethical compliance."
        )

        user_proxy = autogen.UserProxyAgent(
            name="UserProxy",
            human_input_mode="NEVER",
            code_execution_config=False,
            default_auto_reply="",
            is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE")
        )
        user_proxy.register_function(
            function_map={
                "run_metasploit_command": lambda module_type, module_name, options: run_metasploit_command(msf_client, module_type, module_name, options)
            }
        )
        groupchat = autogen.GroupChat(agents=[vuln_decider, ethics, user_proxy], messages=[])
        manager = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})
        manager.initiate_chat(
            user_proxy,
            message=f"Assess vulnerabilities for IP {state['ip']}. Scan results: {state['scan_results']}. Previous plan: {state['messages'][-1]['content'] if state['messages'] else 'No plan.'}"
        )
        executed_output = [msg['content'] for msg in groupchat.messages if 'tool_calls' in msg or 'function_call' in msg]
        state['vulns'] = executed_output if executed_output else ["No vulnerabilities assessed."]
        state['messages'].extend(groupchat.messages)
    
    except Exception as e:
        state['vulns'] = [f"Error: {str(e)}"]
    finally:
        container.remove(force=True)
    return state

# AutoGen exploitation node
def exploitation_node(state: ReconState) -> ReconState:
    state['exploitation_attempt'] = True
    state['shell_success'] = False
    if state['vulns']:
        client = docker.from_env()
        container = client.containers.run('kali-metasploit', detach=True, ports={'55552/tcp': 55552}, network_mode="host")
        try:
            time.sleep(5)
            msf_client = MsfRpcClient('password', host='localhost', port=55552)
            config_list = choose_llm(state)

            # This agent decide on Metasploit exploit based on vulnarabilities that were found
            exploit_decider = autogen.AssistantAgent(
                name="ExploitDecider",
                llm_config={"config_list": config_list},
                system_message="Based on vulnerabilities, decide on Metasploit exploit modules and payloads. Suggest safe, simulated exploits if possible. Provide module type ('exploit'), name, options dict, and payload."
            )

            # This is an ethics agent
            ethics = autogen.AssistantAgent(
                name="EthicsChecker",
                llm_config={"config_list": config_list},
                system_message="Strictly review and approve exploitation attempts for ethical and legal compliance. Block if not authorized."
            )
            user_proxy = autogen.UserProxyAgent(
                name="UserProxy",
                human_input_mode="NEVER",
                code_execution_config=False,
                default_auto_reply="",
                is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE")
            )
            user_proxy.register_function(
                function_map={
                    "run_metasploit_command": lambda module_type, module_name, options: run_metasploit_command(msf_client, module_type, module_name, options)
                }
            )
            groupchat = autogen.GroupChat(agents=[exploit_decider, ethics, user_proxy], messages=[])
            manager = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})
            manager.initiate_chat(
                user_proxy,
                message=f"Decide and attempt exploitation for IP {state['ip']}. Vulns: {state['vulns']}. Ensure ethical approval."
            )
            executed_output = [msg['content'] for msg in groupchat.messages if 'tool_calls' in msg or 'function_call' in msg]
            state['shell_success'] = "job_id" in executed_output[-1] if executed_output else False  # Simplified check
            state['scan_results']['exploit'] = executed_output if executed_output else "No exploitation output."
            state['messages'].extend(groupchat.messages)
        except Exception as e:
            state['scan_results']['exploit'] = f"Exploit failed: {str(e)}"
        finally:
            container.remove(force=True)
    return state

# AutoGen analysis node
def analysis_node(state: ReconState) -> ReconState:
    config_list = choose_llm(state)

    # Initializing Analyst agent 
    analyst = autogen.AssistantAgent(
        name="Analyst",
        llm_config={"config_list": config_list},
        system_message="Analyze scan results and vulnerabilities."
    )

    # Initializing Reporter agent 
    reporter = autogen.AssistantAgent(
        name="Reporter",
        llm_config={"config_list": config_list},
        system_message="Generate a detailed report summarizing findings."
    )

    user_proxy = autogen.UserProxyAgent(name="UserProxy", human_input_mode="NEVER")
    groupchat = autogen.GroupChat(agents=[analyst, reporter, user_proxy], messages=[])
    manager = autogen.GroupChatManager(groupchat=groupchat, llm_config={"config_list": config_list})
    manager.initiate_chat(user_proxy, message=f"Analyze: {state['scan_results']} and vulns: {state['vulns']}. Generate report.")
    state['messages'].extend(groupchat.messages)
    state['report'] = groupchat.messages[-1]['content'] if groupchat.messages else "No analysis available."
    return state

workflow = StateGraph(ReconState)

# Adding nodes
workflow.add_node("planning", planning_node)
workflow.add_node("scan", scan_node)
workflow.add_node("vuln_assessment", vuln_assessment_node)
workflow.add_node("exploitation", exploitation_node)
workflow.add_node("analysis", analysis_node)

#Settign entry point and defining edges 
workflow.set_entry_point("planning")
workflow.add_edge("planning", "scan")
workflow.add_edge("scan", "vuln_assessment")
workflow.add_edge("vuln_assessment", "exploitation")
workflow.add_edge("exploitation", "analysis")
workflow.add_edge("analysis", END)

app = workflow.compile()