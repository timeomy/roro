package observe

// OpenTelemetry attribute and metric names.
//
// Source: OpenTelemetry GenAI semantic conventions, which moved from
// open-telemetry/semantic-conventions to
// https://github.com/open-telemetry/semantic-conventions-genai
// (docs/gen-ai/mcp.md and docs/gen-ai/execute-tool.md), read on 2026-11-16.
// Status there: Development. Names may change; testdata/semconv-genai-mcp.json
// pins the names used here and semconv_test.go fails if they drift apart, so a
// rename is a deliberate, reviewed change.
const (
	// MCP span name: "{mcp.method.name} {target}", e.g. "tools/call read_file".
	AttrMCPMethodName      = "mcp.method.name"
	AttrMCPSessionID       = "mcp.session.id"
	AttrMCPProtocolVersion = "mcp.protocol.version"
	AttrJSONRPCRequestID   = "jsonrpc.request.id"
	AttrGenAIToolName      = "gen_ai.tool.name"
	AttrGenAIOperationName = "gen_ai.operation.name"
	AttrGenAIAgentName     = "gen_ai.agent.name"
	AttrNetworkTransport   = "network.transport"
	AttrErrorType          = "error.type"

	// Values.
	OperationExecuteTool = "execute_tool"
	MethodToolsCall      = "tools/call"
	TransportPipe        = "pipe" // stdio
	TransportTCP         = "tcp"  // HTTP
	ErrorTypeToolError   = "tool_error"

	// Metrics.
	MetricServerOperationDuration = "mcp.server.operation.duration" // histogram, seconds
)

// Tollgate-specific attributes and metrics (not part of semantic conventions).
const (
	AttrDecision   = "tollgate.decision"
	AttrReason     = "tollgate.reason"
	AttrPolicyIDs  = "tollgate.policy_ids"
	AttrServer     = "tollgate.server"
	AttrApprovalID = "tollgate.approval_id"

	MetricDecisions = "tollgate.decisions" // counter
)
