/**
 * 基础设施层：本地 RAG 知识检索（规范 §5.2 infrastructure/knowledge/）。
 *
 * 定位：私有证据语料的小型确定性检索，零第三方依赖、语料不出沙箱：
 * - 向量：确定性哈希词袋嵌入（embed），同输入必得同向量；
 * - 排序：余弦相似度（0.7）+ 词项重合率重排（0.3）；
 * - 拒绝口径：空语料 / 最高分低于阈值时显式返回 insufficient_evidence，
 *   绝不返回"看起来相关"的弱证据（规范红线 2：证据不足走显式分支）；
 * - 语料契约：逐行校验禁止字段（样本字节 / 路径 / 凭据），失败即抛错关闭。
 */
import fs from 'node:fs';

/** 语料禁止字段：任何一行出现即拒绝加载整份语料。 */
const FORBIDDEN_FIELDS = new Set(['apk', 'binary', 'bytes', 'file_path', 'sample_path', 'token', 'secret', 'api_key']);

/** 分词：英文按标识符切分，中文按单字切分。 */
function tokenize(value) {
  return (String(value ?? '').toLowerCase().match(/[a-z0-9_.-]+|[\u4e00-\u9fff]/g) ?? []).filter((item) => item.length > 1 || /[\u4e00-\u9fff]/.test(item));
}

/** FNV-1a 哈希：把 token 映射到向量维度（确定性嵌入的基础）。 */
function hash(token, size) {
  let value = 2166136261;
  for (const char of token) value = Math.imul(value ^ char.charCodeAt(0), 16777619);
  return (value >>> 0) % size;
}

/** 确定性本地嵌入：适合小型私有证据语料（归一化词袋向量）。 */
export function embed(text, dimensions = 128) {
  const vector = new Float64Array(dimensions);
  for (const token of tokenize(text)) vector[hash(token, dimensions)] += 1;
  const norm = Math.hypot(...vector);
  return norm === 0 ? vector : Float64Array.from(vector, (value) => value / norm);
}

function cosine(a, b) {
  return a.reduce((sum, value, index) => sum + value * b[index], 0);
}

function overlap(query, text) {
  const queryTerms = new Set(tokenize(query));
  const textTerms = new Set(tokenize(text));
  if (!queryTerms.size) return 0;
  return [...queryTerms].filter((term) => textTerms.has(term)).length / queryTerms.size;
}

export function splitDocument(text, { chunkSize = 420, overlapSize = 80 } = {}) {
  const normalized = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (!normalized) return [];
  const chunks = [];
  for (let start = 0; start < normalized.length; start += chunkSize - overlapSize) {
    chunks.push(normalized.slice(start, start + chunkSize));
    if (start + chunkSize >= normalized.length) break;
  }
  return chunks;
}

export function loadRagCorpusJsonl(filePath) {
  const chunks = [];
  for (const [index, line] of fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).entries()) {
    let record;
    try { record = JSON.parse(line); } catch { throw new Error(`RAG 语料第 ${index + 1} 行不是有效 JSON`); }
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error(`RAG 语料第 ${index + 1} 行必须是对象`);
    if (Object.keys(record).some((key) => FORBIDDEN_FIELDS.has(key.toLowerCase()))) {
      throw new Error(`RAG 语料第 ${index + 1} 行包含禁止字段`);
    }
    const id = String(record.id ?? record.doc_id ?? '').trim();
    const text = String(record.text ?? '').trim();
    const title = String(record.title ?? id).trim();
    const sourceRef = String(record.source_ref ?? id).trim();
    if (!id || !text || !sourceRef) throw new Error(`RAG 语料第 ${index + 1} 行缺少 id、text 或 source_ref`);
    splitDocument(text).forEach((content, chunkIndex) => chunks.push({
      citationId: `${id}#${chunkIndex + 1}`, sourceRef, title, content, embedding: embed(content)
    }));
  }
  return chunks;
}

/** 本地检索器：嵌入召回 + 词项重排，取 topK 且最高分不得低于 minScore。 */
export class LocalRagRetriever {
  constructor({ chunks, topK = 3, minScore = 0.18 }) {
    this.chunks = chunks;
    this.topK = Math.max(1, Math.min(Number(topK) || 3, 8));
    this.minScore = Math.max(0, Math.min(Number(minScore) || 0.18, 1));
  }

  retrieve(query) {
    if (!this.chunks.length) return { status: 'insufficient_evidence', reason: 'empty_corpus', citations: [] };
    const queryEmbedding = embed(query);
    const ranked = this.chunks.map((chunk) => {
      const embeddingScore = cosine(queryEmbedding, chunk.embedding);
      const rerankScore = overlap(query, chunk.content);
      return { ...chunk, score: embeddingScore * 0.7 + rerankScore * 0.3 };
    }).sort((a, b) => b.score - a.score || a.citationId.localeCompare(b.citationId)).slice(0, this.topK);
    if (!ranked.length || ranked[0].score < this.minScore) {
      return { status: 'insufficient_evidence', reason: 'score_below_threshold', citations: [], topScore: ranked[0]?.score ?? 0 };
    }
    return {
      status: 'grounded', topScore: ranked[0].score,
      citations: ranked.map(({ citationId, sourceRef, title, content, score }) => ({ citationId, sourceRef, title, snippet: content, score }))
    };
  }
}

/** 组装检索查询：报告画像 + 评分证据 + 行为 / 字符串 / 网络指标。 */
export function ragQuery(report, assessment) {
  return [report.profile, ...assessment.evidence.map((item) => `${item.tag} ${item.reason}`),
    ...report.findings.behaviors, ...report.findings.stringIndicators, ...report.findings.networkIndicators].join(' ');
}

/** 从环境变量装配检索器：未配置返回 not_configured；加载失败返回 unavailable（不外泄路径细节）。 */
export function retrieverFromEnvironment(env = process.env) {
  const path = env.MALWARE_TRIAGE_RAG_CORPUS_PATH;
  if (!path) return { retrieve: () => ({ status: 'not_configured', citations: [] }) };
  try {
    return new LocalRagRetriever({ chunks: loadRagCorpusJsonl(path), topK: env.MALWARE_TRIAGE_RAG_TOP_K, minScore: env.MALWARE_TRIAGE_RAG_MIN_SCORE });
  } catch {
    // Do not expose a corpus path or parser detail through workflow output.
    return { retrieve: () => ({ status: 'unavailable', reason: 'corpus_load_failed', citations: [] }) };
  }
}
