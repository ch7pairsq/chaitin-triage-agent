const SHA256 = /^[a-f0-9]{64}$/i;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const PROFILES = new Set(['android-apk', 'windows-pe', 'linux-elf']);
const ALLOWED_FIELDS = new Set(['event_id', 'source', 'occurred_at', 'event_type', 'sample_ref', 'sha256', 'profile']);

/**
 * Validate an alert before it can become a workflow request.  This is an
 * adapter for scheduler/webhook consumers, not a public HTTP endpoint: a
 * deployment must authenticate its ingress outside the Agent guest.
 */
export function normalizeAlertEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('事件必须是 JSON 对象');
  const forbidden = Object.keys(input).filter((key) => !ALLOWED_FIELDS.has(key));
  if (forbidden.length) throw new Error(`事件包含禁止字段：${forbidden.join(',')}`);
  const eventId = String(input.event_id ?? '').trim();
  const source = String(input.source ?? '').trim();
  const eventType = String(input.event_type ?? '').trim();
  const sampleRef = String(input.sample_ref ?? '').trim();
  const sha256 = String(input.sha256 ?? '').trim().toLowerCase();
  const profile = String(input.profile ?? '').trim();
  if (!SAFE_ID.test(eventId) || !SAFE_ID.test(source) || !SAFE_ID.test(eventType) || !SAFE_ID.test(sampleRef)) throw new Error('事件标识或样本引用格式无效');
  if (!SHA256.test(sha256) || !PROFILES.has(profile)) throw new Error('事件缺少有效 SHA-256 或 profile');
  if (input.occurred_at && Number.isNaN(Date.parse(input.occurred_at))) throw new Error('occurred_at 必须是有效时间');
  return { eventId, source, eventType, sampleRef, sha256, profile, occurredAt: input.occurred_at ?? null };
}

export class EventIngress {
  constructor({ stateStore, workflow }) {
    this.stateStore = stateStore;
    this.workflow = workflow;
  }

  async handle(input) {
    const event = normalizeAlertEvent(input);
    const existing = await this.stateStore.getIngressEvent(event.eventId);
    if (existing) return { action: 'DUPLICATE_EVENT_IGNORED', eventId: event.eventId, traceId: existing.traceId, status: existing.status };
    const result = await this.workflow.run({ sampleId: event.sampleRef, sha256: event.sha256, profile: event.profile });
    await this.stateStore.saveIngressEvent({
      eventId: event.eventId, source: event.source, eventType: event.eventType,
      traceId: result.traceId, status: result.action
    });
    return { eventId: event.eventId, source: event.source, eventType: event.eventType, ...result };
  }
}
