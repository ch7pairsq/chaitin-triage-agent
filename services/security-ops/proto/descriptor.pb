
ñ$
security_ops.protosecurity.ops.v1"Á
IngestAlertEventRequest
event_id (	ReventId$
wazuh_alert_id (	RwazuhAlertId%
correlation_id (	RcorrelationId
occurred_at (	R
occurredAt

alert_json (	R	alertJson"’
IngestAlertEventResponse
event_id (	ReventId%
correlation_id (	RcorrelationId
status (	Rstatus
	duplicate (R	duplicate"Š
AlertRef
event_id (	ReventId%
correlation_id (	RcorrelationId$
wazuh_alert_id (	RwazuhAlertId
status (	Rstatus"0
ListPendingAlertsRequest
limit (Rlimit"N
ListPendingAlertsResponse1
alerts (2.security.ops.v1.AlertRefRalerts"w
ClaimAlertRequest
event_id (	ReventId(
scheduler_run_id (	RschedulerRunId

sandbox_id (	R	sandboxId"€
ClaimAlertResponse
trace_id (	RtraceId
event_id (	ReventId
status (	Rstatus
	duplicate (R	duplicate"3
GetAlertContextRequest
event_id (	ReventId" 
GetAlertContextResponse
event_id (	ReventId%
correlation_id (	RcorrelationId$
wazuh_alert_id (	RwazuhAlertId

alert_json (	R	alertJson"/
EnrichAlertRequest
trace_id (	RtraceId"»
EnrichAlertResponse
trace_id (	RtraceId!
context_json (	RcontextJson#
evidence_refs (	RevidenceRefs
	domain_id (	RdomainId$
attack_type_id (	RattackTypeId"˜
MatchKnowledgeRequest
trace_id (	RtraceId
	domain_id (	RdomainId$
attack_type_id (	RattackTypeId!
context_json (	RcontextJson"©
KnowledgeMatch!
knowledge_id (	RknowledgeId$
applicability (	Rapplicability#
evidence_refs (	RevidenceRefs)
missing_evidence (	RmissingEvidence"n
MatchKnowledgeResponse
trace_id (	RtraceId9
matches (2.security.ops.v1.KnowledgeMatchRmatches"z
EvaluatePolicyRequest
trace_id (	RtraceId!
context_json (	RcontextJson#
knowledge_ids (	RknowledgeIds"Ö
EvaluatePolicyResponse
trace_id (	RtraceId
decision (	Rdecision
action (	Raction#
evidence_refs (	RevidenceRefs%
knowledge_refs (	RknowledgeRefs'
ticket_required (RticketRequired#
policy_status (	RpolicyStatus,
auto_close_allowed (RautoCloseAllowed%
decision_token	 (	RdecisionToken"{
RecordTriageResultRequest
trace_id (	RtraceId%
decision_token (	RdecisionToken
	narrative (	R	narrative"r
RecordTriageResultResponse
	result_id (	RresultId
trace_id (	RtraceId
	duplicate (R	duplicate"S
CreateManualTicketRequest
trace_id (	RtraceId
	result_id (	RresultId"W
CreateManualTicketResponse
	ticket_id (	RticketId
	duplicate (R	duplicate"X
QueueFeishuNotificationRequest
trace_id (	RtraceId
	ticket_id (	RticketId"x
QueueFeishuNotificationResponse
delivery_id (	R
deliveryId
status (	Rstatus
	duplicate (R	duplicate"2
FinalizeTriageRequest
trace_id (	RtraceId"I
FinalizeTriageResponse
trace_id (	RtraceId
state (	Rstate"2
GetTriageTraceRequest
trace_id (	RtraceId"R
GetTriageTraceResponse
trace_id (	RtraceId

trace_json (	R	traceJson"U
RecoverDeliveryRequest
limit (Rlimit%
include_manual (RincludeManual"i
RecoverDeliveryResponse
	recovered (R	recovered
pending (Rpending
manual (Rmanual2Î

SecurityOpsServiceg
IngestAlertEvent(.security.ops.v1.IngestAlertEventRequest).security.ops.v1.IngestAlertEventResponsej
ListPendingAlerts).security.ops.v1.ListPendingAlertsRequest*.security.ops.v1.ListPendingAlertsResponseU

ClaimAlert".security.ops.v1.ClaimAlertRequest#.security.ops.v1.ClaimAlertResponsed
GetAlertContext'.security.ops.v1.GetAlertContextRequest(.security.ops.v1.GetAlertContextResponseX
EnrichAlert#.security.ops.v1.EnrichAlertRequest$.security.ops.v1.EnrichAlertResponsea
MatchKnowledge&.security.ops.v1.MatchKnowledgeRequest'.security.ops.v1.MatchKnowledgeResponsea
EvaluatePolicy&.security.ops.v1.EvaluatePolicyRequest'.security.ops.v1.EvaluatePolicyResponsem
RecordTriageResult*.security.ops.v1.RecordTriageResultRequest+.security.ops.v1.RecordTriageResultResponsem
CreateManualTicket*.security.ops.v1.CreateManualTicketRequest+.security.ops.v1.CreateManualTicketResponse|
QueueFeishuNotification/.security.ops.v1.QueueFeishuNotificationRequest0.security.ops.v1.QueueFeishuNotificationResponsea
FinalizeTriage&.security.ops.v1.FinalizeTriageRequest'.security.ops.v1.FinalizeTriageResponsea
GetTriageTrace&.security.ops.v1.GetTriageTraceRequest'.security.ops.v1.GetTriageTraceResponsed
RecoverDelivery'.security.ops.v1.RecoverDeliveryRequest(.security.ops.v1.RecoverDeliveryResponsebproto3