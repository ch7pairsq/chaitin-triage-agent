import dgram from "node:dgram";
import { pathToFileURL } from "node:url";

const profiles = Object.freeze([
  {
    domain_id: "vehicle_platform",
    attack_type_id: "brute_force",
    asset_id: "vehicle-cloud-auth-gateway",
    protocol: "HTTPS",
    srcip: "198.51.100.41",
    dstuser: "fleet-operator",
    outcome: "failed",
    auth_failures: 12,
    window_seconds: 180,
    distinct_accounts: 4,
    authorization_valid: false,
    observed_evidence: ["认证失败与成功日志", "来源地址与设备身份", "账号状态和授权变更记录"]
  },
  {
    domain_id: "iot_platform",
    attack_type_id: "unauthorized_access",
    asset_id: "iot-device-management-api",
    protocol: "MQTT",
    srcip: "198.51.100.42",
    dstuser: "device-service",
    outcome: "allowed",
    protected_resource: true,
    authorization_valid: false,
    protected_action_succeeded: true,
    public_resource: false,
    observed_evidence: ["身份认证与授权日志", "资源权限策略", "请求和响应状态"]
  },
  {
    domain_id: "industrial_internet",
    attack_type_id: "command_execution",
    asset_id: "industrial-edge-gateway",
    protocol: "OPC-UA",
    srcip: "198.51.100.43",
    dstuser: "edge-runtime",
    outcome: "executed",
    untrusted_input_reached_shell: true,
    shell_child_process: true,
    execution_side_effect: true,
    authorization_valid: false,
    observed_evidence: ["进程树与命令行", "应用调用链和网络连接", "命令执行结果"]
  }
]);

export function buildEvent({ sequence, now = new Date() }) {
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new TypeError("sequence must be a non-negative safe integer");
  const profile = profiles[sequence % profiles.length];
  return {
    security_program: "triage_event_injector",
    event_version: "1",
    event_id: `test-event-${now.getTime()}-${sequence}`,
    occurred_at: now.toISOString(),
    authorized: false,
    ...profile
  };
}

export function sendEvent(event, { host, port, socketFactory = () => dgram.createSocket("udp4") }) {
  if (!host) return Promise.reject(new TypeError("WAZUH_SYSLOG_HOST is required"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return Promise.reject(new TypeError("WAZUH_SYSLOG_PORT is invalid"));
  const payload = Buffer.from(JSON.stringify(event));
  const socket = socketFactory();
  return new Promise((resolve, reject) => {
    socket.send(payload, port, host, (error) => {
      socket.close();
      if (error) reject(error);
      else resolve({ bytes: payload.length, eventId: event.event_id });
    });
  });
}

export async function run({
  host = process.env.WAZUH_SYSLOG_HOST,
  port = Number(process.env.WAZUH_SYSLOG_PORT ?? 514),
  intervalMs = Number(process.env.INJECT_INTERVAL_MS ?? 300_000),
  enabled = String(process.env.INJECT_ENABLED ?? "false").toLowerCase() === "true",
  once = String(process.env.INJECT_ONCE ?? "false").toLowerCase() === "true",
  stayAlive = String(process.env.INJECT_STAY_ALIVE ?? "false").toLowerCase() === "true",
  socketFactory,
  waitForShutdown = () => new Promise((resolve) => {
    const timer = setInterval(() => {}, 3_600_000);
    const stop = () => {
      clearInterval(timer);
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      resolve();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  })
} = {}) {
  if (!enabled) {
    console.log(JSON.stringify({ status: "disabled" }));
    if (stayAlive) await waitForShutdown();
    return;
  }
  if (!Number.isInteger(intervalMs) || intervalMs < 60_000 || intervalMs > 86_400_000) {
    throw new TypeError("INJECT_INTERVAL_MS must be between 60000 and 86400000");
  }
  let sequence = 0;
  const emit = async () => {
    const event = buildEvent({ sequence: sequence++ });
    const result = await sendEvent(event, { host, port, ...(socketFactory ? { socketFactory } : {}) });
    console.log(JSON.stringify({ status: "sent", eventId: result.eventId, bytes: result.bytes }));
  };
  await emit();
  if (once) return () => {};
  const timer = setInterval(() => emit().catch((error) => console.error(JSON.stringify({ status: "failed", message: error.message }))), intervalMs);
  return () => clearInterval(timer);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch((error) => {
    console.error(JSON.stringify({ status: "failed", message: error.message }));
    process.exitCode = 1;
  });
}
