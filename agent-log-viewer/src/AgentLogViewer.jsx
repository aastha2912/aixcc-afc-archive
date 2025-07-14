import { Buffer } from 'buffer';
import pako from 'pako';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useParams, Link } from 'react-router-dom';
import { Avatar } from 'primereact/avatar';
import { Card } from 'primereact/card';
import { Tree } from 'primereact/tree';
import { Button } from 'primereact/button';
import { Fieldset } from 'primereact/fieldset';
import { Accordion, AccordionTab } from 'primereact/accordion';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Dropdown } from 'primereact/dropdown';
import { Tooltip } from 'primereact/tooltip';
import 'primeflex/primeflex.css';
import 'primeicons/primeicons.css';
import 'primereact/resources/primereact.css';
import 'primereact/resources/themes/lara-light-indigo/theme.css';

import './AgentLogViewer.css'

function getAgents(logsUrl) {
    return new Promise(res => {
        const worker = new Worker(new URL("./logProcessor.js", import.meta.url));
        worker.postMessage(logsUrl);
        worker.onmessage = (event) => {
            worker.terminate();
            res(event.data);
        };
    })
}

function formatElapsed(elapsed) {
    // Calculate hours, minutes, and seconds
    const hours = Math.floor(elapsed / 3600);
    const minutes = Math.floor((elapsed % 3600) / 60);
    const seconds = (elapsed % 60).toFixed(2); // Keeps 2 decimal places for seconds

    // Return the formatted string
    if (hours > 0) return `${hours}h${minutes}m${seconds}s`;
    if (minutes > 0) return `${minutes}m${seconds}s`;
    return `${seconds}s`;
}

function Value({value}) {
    if (Array.isArray(value)) {
        const columns = {};
        // array of objects, make a table
        if (value.length && typeof value[0] == "object") {
            for (const v of value) {
                for (const k of Object.keys(v)) {
                    columns[k] = true;
                }
            }
            return <DataTable value={value} paginator alwaysShowPaginator={false} rows={10} size="small" >
                {Object.keys(columns).map((col, i) => (
                    <Column key={col} field={col} header={col} body={v => JSON.stringify(v[col])}></Column>
                ))}
            </DataTable>
        }
        // array of something else, use JSON
        return <pre className='value'>{JSON.stringify(value)}</pre>
    } else if (typeof value == "object" && value !== null) {
        return <div>
            {
                Object.entries(value).map(([k, v], idx) => (
                    <KeyValue key={idx} keyName={k} value={v} />
                ))
            }
        </div>
    }
    return <pre className='value'>{value !== null ? value.toString() : "null"}</pre>;
}

function KeyValue({ keyName, value }) {
    return (
        <Fieldset legend={keyName} unstyled>
            <Value value={value}></Value>
        </Fieldset>
    );
}

function ToolCallResponse({ content, call }) {
    const { error, result, extra } = JSON.parse(content);
    return (
        <div className='tool-call-response'>
            {call.agents.map((agent, idx) => (
                <div className="spawned-agent" key={idx}>
                    Spawned agent: <Link to={`../${agent.key}`} relative="path">{agent.label}</Link>
                </div>
            ))}
            {error && <KeyValue keyName="error" value={error} />}
            {result && <KeyValue keyName="result" value={result} />}
            {extra && <KeyValue keyName="extra" value={extra} />}
        </div>
    );
}

function ToolCall({ call }) {
    const { function: { name, arguments: jsonArgs } } = call;
    const args = JSON.parse(jsonArgs);
    const callStr = `${name}(${Object.keys(args).join(', ')})`;
    return (
      <div className='tool-call'>
        <h4><pre>{callStr}</pre></h4>
        {Object.entries(args).map(([key, value], idx) => (
          <KeyValue key={idx} keyName={key} value={value} />
        ))}
      </div>
    );
  }

function AgentDownload({ data }) {
    const ref = useRef(null);
    const [href, setHref] = useState(null);
    const [fileName] = useState("agent.json");

    const handleDownload = (e) => {
        if (!href) {
            e.preventDefault(); // Prevent navigation if the href isn't ready
            const decoded = Buffer.from(data, 'base64');
            const decompressed = pako.ungzip(decoded, { to: 'string' });
            const blob = new Blob([decompressed], { type: 'application/json' });
            const objectUrl = URL.createObjectURL(blob);
            setHref(objectUrl);
            setTimeout(() => { ref.current.click(); }, 0);
        }
    };

    return (
        <div>
            <Tooltip target={ref} content="Download serialized agent before this message" />
            <a ref={ref} href={href || '#'} download={fileName} onClick={handleDownload} >
                <Avatar icon="pi pi-replay" style={{ backgroundColor: 'transparent', border: 'none' }} />
            </a>
        </div>
    );
}

function Logs({ logs }) {
    return (
        <div style={{ fontSize: '10px' }}>
            <Accordion>
                <AccordionTab header="Logs">
                    <DataTable value={logs} paginator alwaysShowPaginator={false} rows={10} size="small">
                        <Column field="level.name" header="level"></Column>
                        <Column field="module" header="module"></Column>
                        <Column field="function" header="function"></Column>
                        <Column field="message" header="message"></Column>
                    </DataTable>
                </AccordionTab>
            </Accordion>
        </div>
    )
}

function Message({ msg }) {
    const ICON_MAP = {
      "system": "pi pi-cog",
      "user": "pi pi-user",
      "assistant": "pi pi-prime",
      "tool": "pi pi-wrench"
    };
    const icon = ICON_MAP[msg.role];
    const hasThinking = msg.thinking_blocks && msg.thinking_blocks.length > 0;
    return (
      <div className='message' role={msg.role}>
        <h3 className="flex align-items-center justify-content-between">
          <span>
            <Avatar icon={icon} size="medium" style={{ backgroundColor: 'transparent', border: 'none' }} />
            {`${msg.role} message${msg.cost ? ': $' + msg.cost.toFixed(3) : ''}`}
          </span>
          <span>
            {msg.pre_serialized && <AgentDownload data={msg.pre_serialized} />}
            {
                (msg.compressions || null) &&
                <div>
                <Avatar icon='pi pi-exclamation-triangle' style={{ backgroundColor: 'transparent', border: 'none' }}/>
                compressions: {msg.compressions}
                </div>
            }
          </span>
          <span>
            <Avatar icon="pi pi-clock" size="medium" style={{ backgroundColor: 'transparent', border: 'none'}} />
            {formatElapsed(msg.elapsed)}
          </span>
        </h3>
        {hasThinking && (
          <div className="thinking-section">
            <h4>Thinking Process</h4>
            {msg.thinking_blocks.map((block, idx) => (
              <div key={idx} className="thinking-block">
                <div className='thinking-content'>
                  <pre>{block.thinking}</pre>
                </div>
              </div>
            ))}
          </div>
        )}
        {!msg.tool_call_id && msg.logs.length > 0 && <Logs logs={msg.logs}/>}
        {!msg.tool_call_id && <div className='content'><pre>{msg.content}</pre></div>}
        {msg.tool_call_id && msg.tool_call.logs && <Logs logs={msg.tool_call.logs} />}
        {msg.tool_call_id && <ToolCallResponse content={msg.content} call={msg.tool_call} />}
        {msg.tool_calls && msg.tool_calls.map((call, idx) => <ToolCall call={call} key={idx} />)}
      </div>
    );
  }

function Conversation({ agent }) {
    return (
        <Card title={`${agent.label} Conversation: $${agent.data.total_cost.toFixed(3)}`}>
            {agent.data.messages.map((msg, idx) => (
                <Message msg={msg} key={idx} />
            ))}
        </Card>
    );
}

function AgentLogViewer() {
    const topRef = useRef();
    const [logs, setLogs] = useState([]);
    const [agents, setAgents] = useState([]);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [loading, setLoading] = useState(false);
    const { logName, selectedAgentKey } = useParams();
    const navigate = useNavigate();

    const refreshLogs = () => {
        setLoading(true);
        // Fetch logs from the server
        fetch('/logs')
        .then(response => response.json())
        .then(data => setLogs(data))
        .catch(error => console.error('Error fetching logs:', error))
        .then(() => setLoading(false));
    }
    useEffect(refreshLogs, []);
    const handleKeyPress = useCallback((event) => {
        if (event.key === 'r') {
            refreshLogs();
        }
    }, []);
    useEffect(() => {
        document.addEventListener("keydown", handleKeyPress);
        return () => {
            document.removeEventListener("keydown", handleKeyPress);
        };
    }, [handleKeyPress]);

    useEffect(() => {
        if (selectedAgentKey === undefined) return setSelectedAgent(null);
        const findAgentByKey = (agents, key) => {
            for (let agent of agents) {
                if (agent.key === key) {
                    return agent;
                }
                const found = findAgentByKey(agent.children, key);
                if (found) {
                    agent.expanded = true;
                    return found;
                }
            }
            return null;
        };
        const agent = findAgentByKey(agents, selectedAgentKey);
        setSelectedAgent(agent);
    }, [selectedAgentKey, agents]);

    useEffect(() => {
        if (logName === undefined) return setAgents([]);
        const logUrl = `/logs/${logName}`;
        setLoading(true);
        getAgents(logUrl)
            .then(agents => setAgents(agents))
            .catch(error => console.error('Fetch error:', error))
            .then(() => setLoading(false));
    }, [logs, logName]);

    const onLogSelect = (e) => {
        // Navigate to the selected log
        if (logName && selectedAgentKey) {
            navigate(`../../${e.value}`, { relative: 'path' })
        } else if (logName) {
            navigate(`../${e.value}`, { relative: 'path' })
        } else {
            navigate(`${e.value}`, { relative: 'path' });
        }
    };

    const onAgentSelect = (e) => {
        setSelectedAgent(e.node);
        if (selectedAgentKey) {
            navigate(`../${e.node.key}`, { relative: 'path' });
        } else {
            navigate(`${e.node.key}`, { relative: 'path' });
        }
    };

    const setExpanded = (agents, expanded) => {
        for (const agent of agents) {
            agent.expanded = expanded;
            setExpanded(agent.children, expanded);
        }
    };

    const expandAll = () => {
        setExpanded(agents, true);
        setAgents([...agents]);
    };

    const collapseAll = () => {
        setExpanded(agents, false);
        setAgents([...agents]);
    };

    const onAgentCollapse = (e) => {
        e.node.expanded = false;
        setAgents([...agents]);
    }

    const totalCost = agents.reduce((acc, agent) => acc + agent.data.total_cost, 0);

    return (
        <div>
            <div className="agent-log-viewer-container">
                <div className="tree-container">
                    <div className="flex flex-wrap gap-2 mb-4">
                        <div className="w-full flex">
                            <Button
                                type="button"
                                icon="pi pi-refresh"
                                className="p-button-rounded p-button-text p-button-sm mr-2"
                                onClick={refreshLogs}
                                aria-label="Refresh Logs"
                                tooltip="Refresh logs"
                                tooltipOptions={{position: 'top'}}
                            />
                            <Dropdown
                                placeholder="Select a log file"
                                value={logName}
                                onChange={onLogSelect}
                                options={logs}
                                optionLabel="name"
                                style={{ width: "100%" }}
                            />
                        </div>
                        <div className="w-full flex gap-2 mt-2">
                            <Button className="w-6" type="button" icon="pi pi-plus" label="Expand All" onClick={expandAll} />
                            <Button className="w-6" type="button" icon="pi pi-minus" label="Collapse All" onClick={collapseAll} />
                        </div>
                    </div>
                    { loading ? "loading agents..." :
                        <div>
                            <div className="mb-2 text-md text-gray-700">
                                Total agent cost: <strong>${totalCost.toFixed(3)}</strong>
                            </div>
                            <Tree
                                value={agents}
                                selectionMode="single"
                                selectionKeys={selectedAgent?.key ?? null}
                                onSelect={onAgentSelect}
                                onCollapse={onAgentCollapse}
                            />
                        </div>
                    }
                </div>
                <div className="conversation-container">
                    { loading ? "loading agents..." :
                        <div>
                            <div ref={topRef}></div>
                            {
                                selectedAgent &&
                                <Conversation agent={selectedAgent} />
                            }
                        </div>
                    }
                </div>
            </div>
        </div>
    );
}

export default AgentLogViewer;