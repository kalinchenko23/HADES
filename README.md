# Hedes Refactoring Proposal

As discussed during our meeting and in my presentation to SOF-S leadership, the refactored Hades will primarily focus on the reconnaissance stage of red team TTPs. The primary objective is to establish a shell or, at a minimum, generate a detailed report to assist analysts in selecting an appropriate target exploitation path.

With that in mind, below are the proposed changes to Hades' technology stack.

---

## Frontend

- Reuse the existing React code with minor tweaks.

---

## Backend

- Rewrite the backend in **Golang** and **Python**.  
  - Go's goroutines and channels are a good fit for handling concurrent connections (web requests, WebSocket connections, message queue consumers/producers) with very low overhead.  
  - It's statically typed and considerably faster than Python.  
  - Suggest using **Go RabbitMQ** rather than Python RabbitMQ.

---

## Agentic Framework

For a red team reconnaissance agent, the goal is typically to be thorough, systematic, and to produce a clear, actionable report. I want to ensure that Hades agents check all the boxes in the provided/suggested methodology, and that we will be able to audit them and infer the decision-making process.  

This aligns well with the strengths of **LangGraph**, which has the following attributes:

### Pros
- **Robust & Reliable**: The process is guaranteed to run in the defined order for every subdomain.  
- **State Management**: The graph structure inherently manages the state (e.g., which subdomains have been scanned).  
- **Clear & Auditable**: The execution path is a clear trace. We will know exactly what was done, what was found, and where failures occurred.  
- **Efficiency**: Great for parallelizing tasks (scanning multiple subdomains simultaneously).

### Cons
- **Less Flexible**: Harder to introduce spontaneous, creative steps. Any new logic (like scanning a discovered GitHub repo) must be explicitly added as a new node and edge in the graph.  
- **More Upfront Design**: The entire workflow must be designed ahead of time.

---

## Hybrid Approach Proposal

Leverage **LangGraph** for overall orchestration and workflow management, while incorporating **AutoGen** agent groups within specific nodes for tasks that benefit from creative problem-solving — for example, an OSINT Agent node.

Admittedly, integrating multiple languages and agentic frameworks will introduce some overhead — increasing efficiency and performance by around **25%**, which might seem modest. However, I believe this richer tech stack will yield significantly greater learning outcomes, potentially doubling the gains compared to a simpler solution.

---

## Summary

I’m confident that the proposed changes to Hades will:
- Result in a more robust product
- Accelerate the growth of our collective skill set

At this stage, I'm not yet ready to provide a diagram. I will create one after deeper research into each framework and completing the initial coding phase.
