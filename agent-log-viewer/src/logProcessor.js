function isAgentConstruction(record) {
    return record.name === "crs.agents.agent" &&
        (record.function === "_log_creation" || record.function === "__init__");
}

function isAgentMessage(record) {
    return record.name === "crs.agents.agent" && record.function === "_append_msg";
}

function isContextCompression(record) {
    return record.name === "crs.agents.agent" && record.function === "_compress_context";
}

function isToolResponse(msg) {
    return msg.role === "tool";
}

function hasToolCalls(msg) {
    return Boolean(msg.tool_calls);
}

function convertToAgentNodes(logData) {
    let agents = {};
    let toolCalls = {};
    for (const log of logData) {
        const record = log.record;
        const agentId = record.extra.running_agent;
        const toolCallId = record.extra.running_tool_call;
        if (isAgentConstruction(record)) {
            const childId = record.extra.agent;
            const child = {
                key: childId,
                parentKey: agentId,
                label: record.extra.name,
                children: [],
                data: { messages: [], logs: [], total_cost: 0.0, compressions: 0 },
                icon: "pi pi-fw pi-prime",
            }
            agents[childId] = child;
            if (agentId !== null) {
                agents[agentId].children.push(child);
            }
            if (toolCallId !== null) {
                toolCalls[toolCallId].agents.push(child);
            }
        } else if (isAgentMessage(record)) {
            const msg = record.extra;
            msg.compressions = agents[msg.agent].data.compressions;
            msg.timestamp = record.time.timestamp;
            const messages = agents[msg.agent].data.messages;
            msg.elapsed = messages.length > 0 ?  msg.timestamp - messages[messages.length-1].timestamp : 0.0;
            if (msg.total_cost) {
                msg.cost = msg.total_cost - (messages.length > 0 ? messages[messages.length-1].total_cost: 0.0);
                agents[msg.agent].data.total_cost = msg.total_cost;
            }
            // attach the pending agent logs to this message, reset the pending agent logs
            msg.logs = agents[msg.agent].data.logs;
            agents[msg.agent].data.logs = [];
            messages.push(msg);
            if (hasToolCalls(msg)) {
                for (const toolCall of msg.tool_calls) {
                    toolCalls[toolCall.id] = {
                        ...toolCall,
                        agents: [],
                        logs: [],
                    };
                }
            }
            if (isToolResponse(msg)) {
                msg.tool_call = toolCalls[msg.tool_call_id];
            }
        } else if (isContextCompression(record)) {
            agents[agentId].data.compressions++;
        } else if (agentId !== null) {
            agents[agentId].data.logs.push(record);
            if (toolCallId != null) {
                toolCalls[toolCallId].logs.push(record);
            }
        }
    }
    return Object.values(agents).filter(agent => agent.parentKey === null);
}

async function fetchLogs(logUrl) {
    const response = await fetch(logUrl);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let logs = [];
    let buffer = '';
    while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let lines = buffer.split(/\r?\n/);
        // Keep the last (possibly incomplete) line in the buffer
        buffer = lines.pop();
        for (const line of lines) {
            if (line.trim()) {
                try {
                    logs.push(JSON.parse(line));
                } catch (e) {
                    console.error('JSON parse error:', line, e);
                }
            }
        }
    }
    // Process the final line if it exists
    if (buffer.trim()) {
        try {
            logs.push(JSON.parse(buffer));
        } catch (e) {
            console.error('JSON parse error:', buffer, e);
        }
    }
    return logs;
}

self.onmessage = function(event) {
    fetchLogs(event.data)
        .then(convertToAgentNodes)
        .then(self.postMessage)
}
