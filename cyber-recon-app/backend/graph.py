from typing import TypedDict, Annotated
from langchain_openai import OpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
import autogen
import docker
import yaml

# Opening and parsing config file
with open('../config/config.yaml') as config_file:
    config=yaml.safe_load(config_file)

# Setting LLM provider
llm_provider = config['llm']['provider']

# Function that chooses model based on the provider
def choose_llm(provider=llm_provider):
    if provider=="ollama":
        return [{"model": config['llm']['local_model'], "base_url": "http://localhost:11434/v1", "api_key": "NULL"}]
    elif provider=="":
        return [{"model": "GPT-4 mini", "api_key": config['llm']['api_key']}]
    
class ReconState(TypedDict):
    ip: str
    messages: Annotated[list, add_messages]
    result: dict

# Creating a dummy AutoGen node for now
def planning_node(state: ReconState) -> ReconState:
    config_list = choose_llm()  # Placeholder LLM
    planner = autogen.AssistantAgent(name="Planner", llm_config={"config_list": config_list})
    user_proxy = autogen.UserProxyAgent(name="UserProxy", human_input_mode="NEVER", code_execution_config={"use_docker": False})
    user_proxy.initiate_chat(planner, message=f"Plan for IP: {state['ip']}")
    state['messages'] = user_proxy.chat_messages[planner]
    state['result'] = {"plan": "Dummy plan complete"}
    return state

#Creating a mock scan of the ip in the containerized enviroment
def mock_offensive_node(state: ReconState) -> ReconState:
    client = docker.from_env()
    container = client.containers.run('alpine', detach=True, command='sleep 10')  # Use alpine for mock; later kali
    exec_result = container.exec_run('echo "Mock scan on ' + state['ip'] + '"')
    state['result']['mock_scan'] = exec_result.output.decode('utf-8')
    container.remove(force=True)
    return state

workflow = StateGraph(ReconState)
workflow.add_node("planning", planning_node)
workflow.add_node("mock_offensive", mock_offensive_node)
workflow.set_entry_point("planning")
workflow.add_edge("planning", "mock_offensive")
workflow.add_edge("mock_offensive", END)
app = workflow.compile()