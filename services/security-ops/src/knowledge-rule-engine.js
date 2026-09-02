const ALLOWED_OPERATORS = new Set([
  "equals",
  "not_equals",
  "in",
  "gte",
  "lte",
  "contains_any",
  "starts_with",
  "truthy",
  "exists"
]);

const ALLOWED_ROOTS = new Set([
  "agent",
  "asset",
  "cluster",
  "data",
  "decoder",
  "destination",
  "domainId",
  "event",
  "full_log",
  "http",
  "identity",
  "location",
  "manager",
  "network",
  "process",
  "protocol",
  "registry",
  "rule",
  "source",
  "timestamp",
  "tls",
  "url"
]);

const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const MAX_PREDICATES = 64;
const MAX_REQUIRED_FACTS = 32;

export function validateKnowledgeRule(rule) {
  if (!isPlainObject(rule)) throw new TypeError("executableRule must be an object");
  if (!/^[1-9][0-9]*\.[0-9]+$/.test(String(rule.version ?? ""))) {
    throw new TypeError("executableRule.version must use major.minor format");
  }
  if (!Array.isArray(rule.requiredFacts) || rule.requiredFacts.length === 0 || rule.requiredFacts.length > MAX_REQUIRED_FACTS) {
    throw new TypeError(`executableRule.requiredFacts must contain 1-${MAX_REQUIRED_FACTS} field paths`);
  }
  const requiredFacts = [...new Set(rule.requiredFacts.map(validateFieldPath))];
  if (requiredFacts.length !== rule.requiredFacts.length) throw new TypeError("executableRule.requiredFacts must be unique");

  const confirmAll = validatePredicateList(rule.confirmWhen?.all, "confirmWhen.all");
  const confirmAny = validatePredicateList(rule.confirmWhen?.any, "confirmWhen.any", { optional: true });
  const excludeAny = validatePredicateList(rule.excludeWhen?.any, "excludeWhen.any", { optional: true });
  const predicateCount = confirmAll.length + confirmAny.length + excludeAny.length;
  if (predicateCount === 0 || predicateCount > MAX_PREDICATES) {
    throw new TypeError(`executableRule must contain 1-${MAX_PREDICATES} predicates`);
  }
  const minimumAny = Number(rule.confirmWhen?.minimumAny ?? (confirmAny.length > 0 ? 1 : 0));
  if (!Number.isInteger(minimumAny) || minimumAny < 0 || minimumAny > confirmAny.length) {
    throw new TypeError("executableRule.confirmWhen.minimumAny is invalid");
  }
  const predicateIds = [...confirmAll, ...confirmAny, ...excludeAny].map((item) => item.predicateId);
  if (new Set(predicateIds).size !== predicateIds.length) throw new TypeError("executableRule predicateId values must be unique");
  if (!isPlainObject(rule.thresholdBasis) || !Array.isArray(rule.thresholdBasis.sourceIds) || rule.thresholdBasis.sourceIds.length === 0) {
    throw new TypeError("executableRule.thresholdBasis.sourceIds must not be empty");
  }
  if (rule.thresholdBasis.sourceIds.some((item) => !/^[a-z0-9][a-z0-9._:-]{2,127}$/.test(String(item)))) {
    throw new TypeError("executableRule.thresholdBasis.sourceIds contains an invalid source id");
  }
  if (!String(rule.thresholdBasis.statement ?? "").trim()) {
    throw new TypeError("executableRule.thresholdBasis.statement must not be empty");
  }
  return rule;
}

export function evaluateKnowledgeRule(rule, context) {
  validateKnowledgeRule(rule);
  const source = isPlainObject(context) ? context : {};
  const missingFacts = rule.requiredFacts.filter((path) => !hasFact(source, path));
  const confirmAll = evaluatePredicates(rule.confirmWhen?.all ?? [], source);
  const confirmAny = evaluatePredicates(rule.confirmWhen?.any ?? [], source);
  const excludeAny = evaluatePredicates(rule.excludeWhen?.any ?? [], source);
  const excludedBy = excludeAny.filter((item) => item.matched);
  const minimumAny = Number(rule.confirmWhen?.minimumAny ?? (confirmAny.length > 0 ? 1 : 0));
  const allMatched = confirmAll.every((item) => item.matched);
  const anyMatched = confirmAny.filter((item) => item.matched).length >= minimumAny;

  let outcome;
  if (excludedBy.length > 0) outcome = "excluded";
  else if (missingFacts.length > 0) outcome = "insufficient";
  else if (allMatched && anyMatched) outcome = "confirmed";
  else outcome = "not_matched";

  const evaluated = [...confirmAll, ...confirmAny];
  return {
    ruleVersion: rule.version,
    outcome,
    matchedPredicates: evaluated.filter((item) => item.matched).map(publicPredicateResult),
    failedPredicates: evaluated.filter((item) => !item.matched).map(publicPredicateResult),
    excludedBy: excludedBy.map(publicPredicateResult),
    missingFacts,
    thresholdSourceIds: [...rule.thresholdBasis.sourceIds]
  };
}

function validatePredicateList(value, field, { optional = false } = {}) {
  if (value === undefined && optional) return [];
  if (!Array.isArray(value) || (!optional && value.length === 0)) throw new TypeError(`executableRule.${field} must be an array`);
  return value.map((predicate, index) => validatePredicate(predicate, `${field}[${index}]`));
}

function validatePredicate(predicate, field) {
  if (!isPlainObject(predicate)) throw new TypeError(`executableRule.${field} must be an object`);
  if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(String(predicate.predicateId ?? ""))) {
    throw new TypeError(`executableRule.${field}.predicateId is invalid`);
  }
  validateFieldPath(predicate.path);
  if (!ALLOWED_OPERATORS.has(predicate.op)) throw new TypeError(`executableRule.${field}.operator is unsupported`);
  if (["gte", "lte"].includes(predicate.op) && !Number.isFinite(predicate.value)) {
    throw new TypeError(`executableRule.${field}.value must be a finite number`);
  }
  if (["in", "contains_any"].includes(predicate.op) && (!Array.isArray(predicate.value) || predicate.value.length === 0 || predicate.value.length > 32)) {
    throw new TypeError(`executableRule.${field}.value must be a non-empty bounded array`);
  }
  if (!["truthy", "exists"].includes(predicate.op) && predicate.value === undefined) {
    throw new TypeError(`executableRule.${field}.value is required`);
  }
  return predicate;
}

function validateFieldPath(value) {
  const path = String(value ?? "");
  const segments = path.split(".");
  if (segments.length === 0 || segments.length > 6 || !ALLOWED_ROOTS.has(segments[0]) ||
      segments.some((segment) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(segment) || FORBIDDEN_SEGMENTS.has(segment))) {
    throw new TypeError(`executableRule field path is not allowed: ${path}`);
  }
  return path;
}

function evaluatePredicates(predicates, context) {
  return predicates.map((predicate) => {
    const actual = readFact(context, predicate.path);
    return { ...predicate, actual, matched: compare(predicate.op, actual, predicate.value) };
  });
}

function compare(operator, actual, expected) {
  if (operator === "exists") return actual !== undefined && actual !== null;
  if (operator === "truthy") return actual === true;
  if (operator === "equals") return scalarEquals(actual, expected);
  if (operator === "not_equals") return actual !== undefined && !scalarEquals(actual, expected);
  if (operator === "gte") return Number.isFinite(Number(actual)) && Number(actual) >= expected;
  if (operator === "lte") return Number.isFinite(Number(actual)) && Number(actual) <= expected;
  if (operator === "in") return expected.some((item) => scalarEquals(actual, item));
  if (operator === "starts_with") return typeof actual === "string" && actual.startsWith(String(expected));
  if (operator === "contains_any") {
    const values = Array.isArray(actual) ? actual : typeof actual === "string" ? [actual] : [];
    return values.some((value) => expected.some((item) => scalarEquals(value, item)));
  }
  return false;
}

function scalarEquals(left, right) {
  return ["string", "number", "boolean"].includes(typeof left) && left === right;
}

function hasFact(context, path) {
  const value = readFact(context, path);
  return value !== undefined && value !== null && value !== "";
}

function readFact(context, path) {
  let value = context;
  for (const segment of path.split(".")) {
    if (!isPlainObject(value) || !Object.hasOwn(value, segment)) return undefined;
    value = value[segment];
  }
  return value;
}

function publicPredicateResult({ predicateId, path, op, value, actual }) {
  return { predicateId, path, op, expected: value, actual };
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
