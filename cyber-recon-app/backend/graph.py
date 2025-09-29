from langgraph.graph import StateGraph, END
from tools import tool_node 
from nodes import ( ReconState,
                    planning_node, 
                    vuln_assessment_node, 
                    scan_node, 
                    post_exploitation_node, 
                    exploitation_node,
                    analysis_node,
                    should_continue_scanning,
                    should_continue_to_post_exploit )

# Create the workflow
def create_recon_workflow():
    """Create workflow with conditional scanning logic and recursion limit"""
    workflow = StateGraph(ReconState)
    
    # Adding all nodes
    workflow.add_node("planning", planning_node)
    workflow.add_node("scan", scan_node) 
    workflow.add_node("vuln_assessment", vuln_assessment_node)
    workflow.add_node("exploitation", exploitation_node)
    workflow.add_node("post_exploitation", post_exploitation_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("tools", tool_node)
    
    # Creating edges
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


# State initialization helper
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

