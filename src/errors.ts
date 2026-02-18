/*
 * AgeCheck-core
 * Copyright (c) 2026 ReallyMe LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export const ErrorCode = {
  INVALID_INPUT: "invalid_input",
  INVALID_HEADER: "invalid_header",
  INVALID_ISSUER: "invalid_issuer",
  INVALID_CREDENTIAL: "invalid_credential",
  INVALID_AGE_TIER: "invalid_age_tier",
  INSUFFICIENT_AGE_TIER: "insufficient_age_tier",
  SESSION_BINDING_REQUIRED: "session_binding_required",
  SESSION_BINDING_MISMATCH: "session_binding_mismatch",
  TOKEN_EXPIRED: "token_expired",
  TOKEN_NOT_YET_VALID: "token_not_yet_valid",
  INVALID_SIGNATURE: "invalid_signature",
  UNKNOWN_KEY_ID: "unknown_key_id",
  INVALID_TOKEN_TYPE: "invalid_token_type",
  VERIFY_FAILED: "verify_failed",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export class AgeCheckError extends Error {
  public readonly code: ErrorCode;

  public constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "AgeCheckError";
    this.code = code;
  }
}
