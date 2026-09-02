
¡1
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

sandbox_id (	R	sandboxId"Ü
ClaimAlertResponse
trace_id (	RtraceId
event_id (	ReventId
status (	Rstatus
	duplicate (R	duplicate
claim_token (	R
claimToken
attempt (Rattempt
lease_until (	R
leaseUntil"T
GetAlertContextRequest
event_id (	ReventId
claim_token (	R
claimToken" 
GetAlertContextResponse
event_id (	ReventId%
correlation_id (	RcorrelationId$
wazuh_alert_id (	RwazuhAlertId

alert_json (	R	alertJson"P
EnrichAlertRequest
trace_id (	RtraceId
claim_token (	R
claimToken"»
EnrichAlertResponse
trace_id (	RtraceId!
context_json (	RcontextJson#
evidence_refs (	RevidenceRefs
	domain_id (	RdomainId$
attack_type_id (	RattackTypeId"¹
MatchKnowledgeRequest
trace_id (	RtraceId
	domain_id (	RdomainId$
attack_type_id (	RattackTypeId!
context_json (	RcontextJson
claim_token (	R
claimToken"©
KnowledgeMatch!
knowledge_id (	RknowledgeId$
applicability (	Rapplicability#
evidence_refs (	RevidenceRefs)
missing_evidence (	RmissingEvidence"n
MatchKnowledgeResponse
trace_id (	RtraceId9
matches (2.security.ops.v1.KnowledgeMatchRmatches"›
EvaluatePolicyRequest
trace_id (	RtraceId!
context_json (	RcontextJson#
knowledge_ids (	RknowledgeIds
claim_token (	R
claimToken"Ö
EvaluatePolicyResponse
trace_id (	RtraceId
decision (	Rdecision
action (	Raction#
evidence_refs (	RevidenceRefs%
knowledge_refs (	RknowledgeRefs'
ticket_required (RticketRequired#
policy_status (	RpolicyStatus,
auto_close_allowed (RautoCloseAllowed%
decision_token	 (	RdecisionToken"œ
RecordTriageResultRequest
trace_id (	RtraceId%
decision_token (	RdecisionToken
	narrative (	R	narrative
claim_token (	R
claimToken"r
RecordTriageResultResponse
	result_id (	RresultId
trace_id (	RtraceId
	duplicate (R	duplicate"t
CreateManualTicketRequest
trace_id (	RtraceId
	result_id (	RresultId
claim_token (	R
claimToken"W
CreateManualTicketResponse
	ticket_id (	RticketId
	duplicate (R	duplicate"y
QueueFeishuNotificationRequest
trace_id (	RtraceId
	ticket_id (	RticketId
claim_token (	R
claimToken"x
QueueFeishuNotificationResponse
delivery_id (	R
deliveryId
status (	Rstatus
	duplicate (R	duplicate"S
FinalizeTriageRequest
trace_id (	RtraceId
claim_token (	R
claimToken"I
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
manual (Rmanual"
RequeueStalledAlertsRequest"‘
RequeueStalledAlertsResponse
scanned (Rscanned
requeued (Rrequeued

manualized (R
manualized
	event_ids (	ReventIds"‡
PutAuthorizationRecordRequest)
authorization_id (	RauthorizationId
status (	Rstatus

scope_type (	R	scopeType
scope_value (	R
scopeValue

valid_from (	R	validFrom
valid_until (	R
validUntil#
evidence_refs (	RevidenceRefs"‚
PutAuthorizationRecordResponse)
authorization_id (	RauthorizationId
status (	Rstatus

updated_at (	R	updatedAt"
GetWorkerReadinessRequest"‰
GetWorkerReadinessResponse
ready (Rready
backlog (Rbacklog
manual (Rmanual1
oldest_pending_age_ms (RoldestPendingAgeMs!
active_batch (RactiveBatch%
accepting_work (RacceptingWork&
last_error_json (	RlastErrorJson2­
SecurityOpsServiceg
IngestAlertEvent(.security.ops.v1.IngestAlertEventRequest).security.ops.v1.IngestAlertEventResponsej
ListPendingAlerts).security.ops.v1.ListPendingAlertsRequest*.security.ops.v1.ListPendingAlertsResponses
RequeueStalledAlerts,.security.ops.v1.RequeueStalledAlertsRequest-.security.ops.v1.RequeueStalledAlertsResponseU

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
RecoverDelivery'.security.ops.v1.RecoverDeliveryRequest(.security.ops.v1.RecoverDeliveryResponsey
PutAuthorizationRecord..security.ops.v1.PutAuthorizationRecordRequest/.security.ops.v1.PutAuthorizationRecordResponsem
GetWorkerReadiness*.security.ops.v1.GetWorkerReadinessRequest+.security.ops.v1.GetWorkerReadinessResponsebproto3