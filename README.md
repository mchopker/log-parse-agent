# log-parse-agent
The log-parse-agent listens for log parse/tail requests on the APIs exposed, and returns the output the the caller.
What application and log files to suppport is configured in the config file ./config/agent-config.json
The agent also supports sharing this configuration periodically to a central server (which becomes the client for this agent).
