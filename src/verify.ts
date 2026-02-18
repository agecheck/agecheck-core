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

import { createLocalJWKSet, createRemoteJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import { AgeCheckError, ErrorCode } from "./errors.js";
import type {
  AgeCheckVerifyConfig,
  JwtClaims,
  VcPayload,
  VcSubject,
  VerifyInput,
  VerifyResult,
  VerifySuccess,
} from "./types.js";

const DEFAULT_PRODUCTION_JWKS_URL = "https://agecheck.me/.well-known/jwks.json";
const DEFAULT_DEMO_JWKS_URL = "https://demo.agecheck.me/.well-known/jwks.json";
const DEFAULT_PRODUCTION_ISSUER = "did:web:agecheck.me";
const DEFAULT_DEMO_ISSUER = "did:web:demo.agecheck.me";
const DEFAULT_REQUIRED_AGE = 18;
const DEFAULT_LEEWAY_SECONDS = 60;
const remoteJwksResolverCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
type IssuerValue = string | string[];

interface NormalizedVerifyConfig {
  allowCustomIssuer: boolean;
  deploymentMode: "production" | "demo";
  jwksUrl: string;
  fallbackJwksUrl?: string;
  localJwks: AgeCheckVerifyConfig["localJwks"];
  issuer: IssuerValue;
  requiredAge: number;
  leewaySeconds: number;
}

function getRemoteJwksResolver(jwksUrl: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = remoteJwksResolverCache.get(jwksUrl);
  if (cached) {
    return cached;
  }

  const resolver = createRemoteJWKSet(new URL(jwksUrl));
  remoteJwksResolverCache.set(jwksUrl, resolver);
  return resolver;
}

function clearRemoteJwksResolver(jwksUrl: string): void {
  remoteJwksResolverCache.delete(jwksUrl);
}

function normalizeConfig(cfg?: AgeCheckVerifyConfig): NormalizedVerifyConfig {
  const allowCustomIssuer = cfg?.allowCustomIssuer ?? false;
  const deploymentMode = cfg?.deploymentMode ?? "production";
  if (deploymentMode !== "production" && deploymentMode !== "demo") {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "Invalid deploymentMode. Expected production or demo.");
  }

  const requiredAge = cfg?.requiredAge ?? DEFAULT_REQUIRED_AGE;
  if (!Number.isInteger(requiredAge) || requiredAge < 0) {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "requiredAge must be a non-negative integer.");
  }

  const leewaySeconds = cfg?.leewaySeconds ?? DEFAULT_LEEWAY_SECONDS;
  if (!Number.isInteger(leewaySeconds) || leewaySeconds < 0 || leewaySeconds > 300) {
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "leewaySeconds must be an integer between 0 and 300.");
  }

  const defaultJwksUrl = deploymentMode === "demo" ? DEFAULT_DEMO_JWKS_URL : DEFAULT_PRODUCTION_JWKS_URL;
  const jwksUrlRaw = cfg?.jwksUrl ?? defaultJwksUrl;
  let jwksUrl: string;
  try {
    const parsed = new URL(jwksUrlRaw);
    if (parsed.protocol !== "https:") {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "jwksUrl must use https.");
    }
    jwksUrl = parsed.toString();
  } catch (error: unknown) {
    if (error instanceof AgeCheckError) {
      throw error;
    }
    throw new AgeCheckError(ErrorCode.INVALID_INPUT, "jwksUrl must be a valid https URL.");
  }

  const defaultIssuer: IssuerValue =
    deploymentMode === "demo" ? [DEFAULT_DEMO_ISSUER, DEFAULT_PRODUCTION_ISSUER] : DEFAULT_PRODUCTION_ISSUER;
  const issuer = cfg?.issuer ?? defaultIssuer;
  const localJwks = cfg?.localJwks ?? { keys: [] };
  const fallbackJwksUrl =
    deploymentMode === "demo" && cfg?.jwksUrl === undefined && (!localJwks || localJwks.keys.length === 0)
      ? DEFAULT_PRODUCTION_JWKS_URL
      : undefined;

  if (!allowCustomIssuer) {
    if (jwksUrl !== defaultJwksUrl) {
      throw new AgeCheckError(
        ErrorCode.INVALID_INPUT,
        "Custom jwksUrl is disabled by default. Set allowCustomIssuer=true to override.",
      );
    }
    if (cfg?.issuer !== undefined) {
      throw new AgeCheckError(
        ErrorCode.INVALID_INPUT,
        "Custom issuer is disabled by default. Set allowCustomIssuer=true to override.",
      );
    }
    if (Array.isArray(localJwks.keys) && localJwks.keys.length > 0) {
      throw new AgeCheckError(
        ErrorCode.INVALID_INPUT,
        "Custom localJwks is disabled by default. Set allowCustomIssuer=true to override.",
      );
    }
  }

  const normalized: NormalizedVerifyConfig = {
    allowCustomIssuer,
    deploymentMode,
    jwksUrl,
    localJwks,
    issuer,
    requiredAge,
    leewaySeconds,
  };
  if (typeof fallbackJwksUrl === "string") {
    normalized.fallbackJwksUrl = fallbackJwksUrl;
  }
  return normalized;
}

function coerceClaims(payload: JWTPayload): JwtClaims {
  return payload as JwtClaims;
}

function parseAgeTier(ageTierRaw: unknown): number {
  if (typeof ageTierRaw !== "string") {
    throw new AgeCheckError(ErrorCode.INVALID_AGE_TIER, "Missing ageTier.");
  }
  if (!/^[1-9]\d*\+$/.test(ageTierRaw)) {
    throw new AgeCheckError(ErrorCode.INVALID_AGE_TIER, "Invalid ageTier value.");
  }
  const numeric = Number.parseInt(ageTierRaw.slice(0, -1), 10);
  if (!Number.isInteger(numeric) || numeric < 1) {
    throw new AgeCheckError(ErrorCode.INVALID_AGE_TIER, "Invalid ageTier value.");
  }
  return numeric;
}

function assertVcClaims(claims: JwtClaims, requiredAge: number): { ageTier: string; ageTierValue: number } {
  const vc = claims.vc;
  if (vc === null || typeof vc !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Missing vc object.");
  }

  const vcPayload = vc as VcPayload;
  const types = vcPayload.type;
  if (!Array.isArray(types) || !types.includes("VerifiableCredential") || !types.includes("AgeTierCredential")) {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Invalid credential type.");
  }

  const subject = vcPayload.credentialSubject;
  if (subject === null || typeof subject !== "object") {
    throw new AgeCheckError(ErrorCode.INVALID_CREDENTIAL, "Missing credentialSubject.");
  }

  const vcSubject = subject as VcSubject;
  const ageTierValue = parseAgeTier(vcSubject.ageTier);
  if (ageTierValue < requiredAge) {
    throw new AgeCheckError(ErrorCode.INSUFFICIENT_AGE_TIER, "Insufficient age tier.");
  }

  return {
    ageTier: String(vcSubject.ageTier),
    ageTierValue,
  };
}

function extractSessionBindingClaim(claims: JwtClaims): string | undefined {
  const vc = claims.vc;
  if (!vc || typeof vc !== "object") {
    return undefined;
  }
  const credentialSubject = (vc as VcPayload).credentialSubject;
  if (!credentialSubject || typeof credentialSubject !== "object") {
    return undefined;
  }
  const session = (credentialSubject as VcSubject).session;
  return typeof session === "string" && session.length > 0 ? session : undefined;
}

function assertSessionBinding(claims: JwtClaims, expectedSession: string | undefined, required: boolean): void {
  const binding = extractSessionBindingClaim(claims);

  if (required && (!expectedSession || typeof binding !== "string")) {
    throw new AgeCheckError(ErrorCode.SESSION_BINDING_REQUIRED, "Session binding is required.");
  }

  if (expectedSession !== undefined) {
    if (typeof binding !== "string") {
      throw new AgeCheckError(
        ErrorCode.SESSION_BINDING_REQUIRED,
        "JWT credentialSubject.session missing while expectedSession was provided.",
      );
    }
    if (binding !== expectedSession) {
      throw new AgeCheckError(ErrorCode.SESSION_BINDING_MISMATCH, "Session binding mismatch.");
    }
  }
}

function mapJoseVerificationError(error: unknown): AgeCheckError | null {
  if (!error || typeof error !== "object") {
    return null;
  }

  const maybe = error as { name?: unknown; claim?: unknown; code?: unknown; message?: unknown };
  const name = typeof maybe.name === "string" ? maybe.name : "";
  const claim = typeof maybe.claim === "string" ? maybe.claim : "";
  const code = typeof maybe.code === "string" ? maybe.code : "";
  const message = typeof maybe.message === "string" ? maybe.message : "";

  if (name === "JWTExpired" || code === "ERR_JWT_EXPIRED") {
    return new AgeCheckError(ErrorCode.TOKEN_EXPIRED, "Token expired.");
  }
  if (name === "JWTClaimValidationFailed" || code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    if (claim === "iss") {
      return new AgeCheckError(ErrorCode.INVALID_ISSUER, "Invalid issuer.");
    }
    if (claim === "nbf") {
      return new AgeCheckError(ErrorCode.TOKEN_NOT_YET_VALID, "Token not valid yet.");
    }
    if (claim === "exp") {
      return new AgeCheckError(ErrorCode.TOKEN_EXPIRED, "Token expired.");
    }
    if (claim === "typ") {
      return new AgeCheckError(ErrorCode.INVALID_TOKEN_TYPE, "Invalid token type.");
    }
  }
  if (name === "JWSSignatureVerificationFailed" || code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
    return new AgeCheckError(ErrorCode.INVALID_SIGNATURE, "Invalid token signature.");
  }
  if (name === "JWKSNoMatchingKey" || code === "ERR_JWKS_NO_MATCHING_KEY") {
    return new AgeCheckError(ErrorCode.UNKNOWN_KEY_ID, "Unknown key ID.");
  }
  if (name === "JWSInvalid" && message.toLowerCase().includes("signature")) {
    return new AgeCheckError(ErrorCode.INVALID_SIGNATURE, "Invalid token signature.");
  }
  return null;
}

function describeUnknownError(error: unknown): string | undefined {
  if (error instanceof Error) {
    return `${error.name}${error.message ? `: ${error.message}` : ""}`;
  }

  if (error && typeof error === "object") {
    const obj = error as {
      name?: unknown;
      code?: unknown;
      message?: unknown;
      claim?: unknown;
    };
    const parts: string[] = [];
    if (typeof obj.name === "string" && obj.name.length > 0) {
      parts.push(`name=${obj.name}`);
    }
    if (typeof obj.code === "string" && obj.code.length > 0) {
      parts.push(`code=${obj.code}`);
    }
    if (typeof obj.claim === "string" && obj.claim.length > 0) {
      parts.push(`claim=${obj.claim}`);
    }
    if (typeof obj.message === "string" && obj.message.length > 0) {
      parts.push(`message=${obj.message}`);
    }
    if (parts.length > 0) {
      return parts.join(" ");
    }
  }

  if (typeof error === "string" && error.length > 0) {
    return error;
  }
  return undefined;
}

export async function verifyAgeToken(input: VerifyInput): Promise<VerifyResult> {
  try {
    if (typeof input.jwt !== "string" || input.jwt.trim() === "") {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "jwt must be a non-empty string.");
    }

    const cfg = normalizeConfig(input.config);

    const protectedHeader = decodeProtectedHeader(input.jwt);
    if (protectedHeader.alg !== "ES256" || typeof protectedHeader.kid !== "string" || protectedHeader.kid.trim() === "") {
      throw new AgeCheckError(ErrorCode.INVALID_HEADER, "JWT header must include ES256 alg and kid.");
    }

    const verifyOnce = async (): Promise<Awaited<ReturnType<typeof jwtVerify>>> => {
      const resolvers =
        cfg.localJwks && cfg.localJwks.keys.length > 0
          ? [createLocalJWKSet(cfg.localJwks)]
          : [
              getRemoteJwksResolver(cfg.jwksUrl),
              ...(cfg.fallbackJwksUrl ? [getRemoteJwksResolver(cfg.fallbackJwksUrl)] : []),
            ];

      let verified: Awaited<ReturnType<typeof jwtVerify>> | null = null;
      let verifyError: unknown = null;
      for (const resolver of resolvers) {
        try {
          verified = await jwtVerify(input.jwt, resolver, {
            algorithms: ["ES256"],
            issuer: cfg.issuer,
            typ: "vc+ld+jwt",
            clockTolerance: cfg.leewaySeconds,
          });
          break;
        } catch (error: unknown) {
          verifyError = error;
        }
      }
      if (verified === null) {
        throw verifyError ?? new Error("JWT verification failed.");
      }
      return verified;
    };

    let verified: Awaited<ReturnType<typeof jwtVerify>>;
    try {
      verified = await verifyOnce();
    } catch (firstError: unknown) {
      const mapped = mapJoseVerificationError(firstError);
      if (mapped?.code !== ErrorCode.UNKNOWN_KEY_ID) {
        throw firstError;
      }

      // Key rotation safety: force-refresh JWKS resolvers once on unknown kid.
      clearRemoteJwksResolver(cfg.jwksUrl);
      if (typeof cfg.fallbackJwksUrl === "string") {
        clearRemoteJwksResolver(cfg.fallbackJwksUrl);
      }
      verified = await verifyOnce();
    }

    const claims = coerceClaims(verified.payload);
    const tier = assertVcClaims(claims, cfg.requiredAge);
    assertSessionBinding(claims, input.expectedSession, input.requireSessionBinding ?? true);

    const success: VerifySuccess = {
      ok: true,
      claims,
      ageTier: tier.ageTier,
      ageTierValue: tier.ageTierValue,
    };

    return success;
  } catch (error: unknown) {
    if (error instanceof AgeCheckError) {
      return {
        ok: false,
        code: error.code,
        message: error.message,
      };
    }

    const joseError = mapJoseVerificationError(error);
    if (joseError) {
      return {
        ok: false,
        code: joseError.code,
        message: joseError.message,
      };
    }

    const detail = describeUnknownError(error);
    return {
      ok: false,
      code: ErrorCode.VERIFY_FAILED,
      message: "Age validation failed.",
      ...(typeof detail === "string" ? { detail } : {}),
    };
  }
}
