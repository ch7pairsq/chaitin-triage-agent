export const ERROR_CODES = Object.freeze({
  INVALID_ARGUMENT: "INVALID_ARGUMENT",
  NOT_FOUND: "NOT_FOUND",
  FAILED_PRECONDITION: "FAILED_PRECONDITION",
  UNAUTHENTICATED: "UNAUTHENTICATED",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  UNAVAILABLE: "UNAVAILABLE",
  DEADLINE_EXCEEDED: "DEADLINE_EXCEEDED",
  RESOURCE_EXHAUSTED: "RESOURCE_EXHAUSTED",
  INTERNAL: "INTERNAL"
});

export const BUSINESS_REASONS = Object.freeze({
  LEASE_BUSY: "LEASE_BUSY",
  LEASE_EXPIRED: "LEASE_EXPIRED",
  CLAIM_FENCED: "CLAIM_FENCED",
  AUTHORIZATION_INVALID: "AUTHORIZATION_INVALID"
});

export class SecurityOpsError extends Error {
  constructor(code, message, details = {}) {
    if (!Object.hasOwn(ERROR_CODES, code)) {
      throw new TypeError(`Unknown SecurityOps error code: ${code}`);
    }
    super(message);
    this.name = "SecurityOpsError";
    this.code = code;
    this.details = details;
  }
}

export function invalidArgument(message, details) {
  return new SecurityOpsError(ERROR_CODES.INVALID_ARGUMENT, message, details);
}

export function notFound(message, details) {
  return new SecurityOpsError(ERROR_CODES.NOT_FOUND, message, details);
}

export function failedPrecondition(message, details) {
  return new SecurityOpsError(ERROR_CODES.FAILED_PRECONDITION, message, details);
}
