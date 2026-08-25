/**
 * 基础设施层：私有威胁证据包加载器（知识库 IO 适配）。
 * 解析与关联的纯逻辑位于 capabilities/security/threat-evidence.js。
 */
import fs from "node:fs";
import { parseThreatEvidenceJsonl } from "../../capabilities/security/threat-evidence.js";

/**
 * 只读取本地私有 JSONL 证据包：调用方显式指定路径，本仓库不内置、不提交、
 * 不联网获取任何 IOC 数据（知识实质性口径见规范 §9.1）。
 */
export function loadThreatEvidenceJsonl(filePath) {
  return parseThreatEvidenceJsonl(fs.readFileSync(filePath, "utf8"));
}
