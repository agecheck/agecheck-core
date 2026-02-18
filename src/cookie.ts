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
import type { JwtClaims, SignedCookieConfig, VerifiedCookiePayload } from "./types.js";

const DEFAULT_COOKIE_NAME = "agecheck_verified";
const DEFAULT_TTL_SECONDS = 86400;

function textEncoder(): TextEncoder {
  return new TextEncoder();
}

function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function isStrictBase64(value: string): boolean {
  if (value.length === 0 || value.length % 4 !== 0) {
    return false;
  }
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function normalizeCookieConfig(cfg: SignedCookieConfig): Required<SignedCookieConfig> {
  if (typeof cfg.secret !== "string" || cfg.secret.length < 32) {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "cookie secret must be at least 32 bytes.");
  }

  const ttlSeconds = cfg.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 60 * 60 * 24 * 365) {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "ttlSeconds must be an integer between 1 and 31536000.");
  }

  const cookieName = cfg.cookieName ?? DEFAULT_COOKIE_NAME;
  if (!/^[A-Za-z0-9_\-]+$/.test(cookieName)) {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "cookieName must be alphanumeric, dash, or underscore.");
  }

  return {
    secret: cfg.secret,
    cookieName,
    ttlSeconds,
  };
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    textEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signPayload(payload: string, secret: string): Promise<string> {
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder().encode(payload));
  return toBase64(new Uint8Array(signature));
}

async function verifyPayloadSignature(payload: string, signatureB64: string, secret: string): Promise<boolean> {
  const key = await importHmacKey(secret);
  const signature = Uint8Array.from(fromBase64(signatureB64));
  return crypto.subtle.verify("HMAC", key, signature, textEncoder().encode(payload));
}

function extractAgeTier(claims: JwtClaims): string {
  const vc = claims.vc;
  if (vc === null || typeof vc !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Missing vc object.");
  }

  const subjectRaw = (vc as Record<string, unknown>).credentialSubject;
  if (subjectRaw === null || typeof subjectRaw !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Missing credentialSubject.");
  }

  const ageTier = (subjectRaw as Record<string, unknown>).ageTier;
  if (typeof ageTier !== "string") {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Missing ageTier.");
  }

  return ageTier;
}

function assertAgeTier(ageTier: string): void {
  if (!/^[1-9]\d*\+$/.test(ageTier)) {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Invalid ageTier.");
  }
}

function parseCookiePayload(json: string): VerifiedCookiePayload | null {
  try {
    const parsed = JSON.parse(json) as unknown;
    if (parsed === null || typeof parsed !== "object") {
      return null;
    }
    const obj = parsed as Record<string, unknown>;

    if (
      obj.verified !== true ||
      typeof obj.exp !== "number" ||
      !Number.isFinite(obj.exp) ||
      !Number.isInteger(obj.exp) ||
      typeof obj.level !== "string"
    ) {
      return null;
    }

    return {
      verified: true,
      exp: obj.exp,
      level: obj.level,
    };
  } catch {
    return null;
  }
}

export async function createVerifiedCookieValue(
  claims: JwtClaims,
  config: SignedCookieConfig,
): Promise<{ cookieName: string; cookieValue: string; payload: VerifiedCookiePayload }> {
  return createVerifiedCookieValueFromLevel(extractAgeTier(claims), config);
}

export async function createVerifiedCookieValueFromLevel(
  level: string,
  config: SignedCookieConfig,
): Promise<{ cookieName: string; cookieValue: string; payload: VerifiedCookiePayload }> {
  assertAgeTier(level);
  const cfg = normalizeCookieConfig(config);
  const now = Math.floor(Date.now() / 1000);

  const payload: VerifiedCookiePayload = {
    verified: true,
    exp: now + cfg.ttlSeconds,
    level,
  };

  const jsonPayload = JSON.stringify(payload);
  const payloadB64 = toBase64(textEncoder().encode(jsonPayload));
  const sig = await signPayload(jsonPayload, cfg.secret);

  return {
    cookieName: cfg.cookieName,
    cookieValue: `${payloadB64}.${sig}`,
    payload,
  };
}

export async function verifySignedCookieValue(
  cookieValue: string,
  config: SignedCookieConfig,
): Promise<VerifiedCookiePayload | null> {
  const cfg = normalizeCookieConfig(config);

  if (typeof cookieValue !== "string" || cookieValue.length === 0) {
    return null;
  }

  const dot = cookieValue.indexOf(".");
  if (dot <= 0 || dot === cookieValue.length - 1) {
    return null;
  }

  const payloadB64 = cookieValue.slice(0, dot);
  const sigB64 = cookieValue.slice(dot + 1);
  if (!isStrictBase64(payloadB64) || !isStrictBase64(sigB64)) {
    return null;
  }

  let jsonPayload: string;
  try {
    jsonPayload = new TextDecoder().decode(fromBase64(payloadB64));
  } catch {
    return null;
  }

  const sigOk = await verifyPayloadSignature(jsonPayload, sigB64, cfg.secret);
  if (!sigOk) {
    return null;
  }

  const payload = parseCookiePayload(jsonPayload);
  if (payload === null) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    return null;
  }

  return payload;
}

export function formatSetCookieHeader(
  cookieName: string,
  cookieValue: string,
  expiresAtUnix: number,
  maxAgeSeconds: number,
): string {
  const expiresUtc = new Date(expiresAtUnix * 1000).toUTCString();
  return `${cookieName}=${cookieValue}; Path=/; Max-Age=${maxAgeSeconds}; Expires=${expiresUtc}; HttpOnly; Secure; SameSite=Lax`;
}
