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

import { AgeCheckError, ErrorCode } from "./errors.js";

export interface WebhookEvent {
  type: string;
  payload: unknown;
}

export function parseWebhookEvent(body: string): WebhookEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "Invalid webhook JSON body.");
  }

  if (parsed === null || typeof parsed !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "Webhook body must be an object.");
  }

  const record = parsed as Record<string, unknown>;
  const type = record.type;
  if (typeof type !== "string" || type.trim() === "") {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "Webhook event type is required.");
  }

  return {
    type,
    payload: record.payload,
  };
}
