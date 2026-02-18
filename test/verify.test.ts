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

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, type KeyLike, type JWK } from "jose";
import { verifyAgeToken } from "../src/verify.js";

let privateKey: KeyLike;
let localJwks: { keys: JWK[] };

async function makeJwt(params: {
  issuer: string;
  ageTier: string;
  credentialSubjectSession?: string;
  kid?: string;
  notBeforeOffsetSeconds?: number;
  expiresInSeconds?: number;
  typ?: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const kid = params.kid ?? "k1";
  const notBeforeOffsetSeconds = params.notBeforeOffsetSeconds ?? -5;
  const expiresInSeconds = params.expiresInSeconds ?? 300;
  const typ = params.typ ?? "vc+ld+jwt";
  const credentialSubjectSession =
    params.credentialSubjectSession ?? "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e";

  const jwtPayload: Record<string, unknown> = {
    vc: {
      type: ["VerifiableCredential", "AgeTierCredential"],
      credentialSubject: {
        id: "did:key:test",
        ageTier: params.ageTier,
        session: credentialSubjectSession,
      },
    },
  };

  return new SignJWT(jwtPayload)
    .setProtectedHeader({ alg: "ES256", kid, typ })
    .setIssuer(params.issuer)
    .setSubject("did:key:test")
    .setIssuedAt(now)
    .setNotBefore(now + notBeforeOffsetSeconds)
    .setExpirationTime(now + expiresInSeconds)
    .sign(privateKey);
}

beforeAll(async () => {
  const pair = await generateKeyPair("ES256");
  privateKey = pair.privateKey;

  const publicJwk = (await exportJWK(pair.publicKey)) as JWK;
  publicJwk.kid = "k1";
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";
  localJwks = { keys: [publicJwk] };
});

afterAll(() => {
  localJwks = { keys: [] };
});

describe("verifyAgeToken", () => {
  it("accepts production token with valid tier and matching session", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "18+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
        requiredAge: 18,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("rejects demo token when in production mode", async () => {
    const jwt = await makeJwt({ issuer: "did:web:demo.agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["invalid_issuer", "verify_failed"]).toContain(result.code);
    }
  });

  it("accepts demo token in demo mode", async () => {
    const jwt = await makeJwt({ issuer: "did:web:demo.agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "demo",
        localJwks,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("accepts production token in demo mode", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "demo",
        localJwks,
        issuer: ["did:web:demo.agecheck.me", "did:web:agecheck.me"],
      },
    });

    expect(result.ok).toBe(true);
  });

  it("rejects insufficient tier", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "18+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
        requiredAge: 21,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("insufficient_age_tier");
    }
  });

  it("accepts 21+ when requiredAge is 18", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
        requiredAge: 18,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("accepts 16+ when requiredAge is 15", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "16+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
        requiredAge: 15,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("accepts 65+ when requiredAge is 18", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "65+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
        requiredAge: 18,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("accepts session binding from vc.credentialSubject.session", async () => {
    const expectedSession = "2f5f16b1-8a69-4d62-8c83-c44be41a188d";
    const jwt = await makeJwt({
      issuer: "did:web:agecheck.me",
      ageTier: "21+",
      credentialSubjectSession: expectedSession,
    });

    const result = await verifyAgeToken({
      jwt,
      expectedSession,
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
      },
    });

    expect(result.ok).toBe(true);
  });

  it("rejects session mismatch", async () => {
    const jwt = await makeJwt({
      issuer: "did:web:agecheck.me",
      ageTier: "21+",
      credentialSubjectSession: "123",
    });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "456",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("session_binding_mismatch");
    }
  });

  it("rejects non-https jwksUrl", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        jwksUrl: "http://example.com/keys.json",
        deploymentMode: "production",
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("invalid_input");
    }
  });

  it("rejects custom issuer override when allowCustomIssuer is false", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        issuer: "did:web:custom.example",
        deploymentMode: "production",
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("invalid_input");
    }
  });

  it("rejects custom jwksUrl when allowCustomIssuer is false", async () => {
    const jwt = await makeJwt({ issuer: "did:web:agecheck.me", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        jwksUrl: "https://issuer.example/.well-known/jwks.json",
        deploymentMode: "production",
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("invalid_input");
    }
  });

  it("accepts custom issuer override only when allowCustomIssuer is true", async () => {
    const jwt = await makeJwt({ issuer: "did:web:issuer.example", ageTier: "21+" });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        localJwks,
        issuer: "did:web:issuer.example",
        deploymentMode: "production",
      },
    });

    expect(result.ok).toBe(true);
  });

  it("returns token_expired for expired token", async () => {
    const jwt = await makeJwt({
      issuer: "did:web:agecheck.me",
      ageTier: "21+",
      notBeforeOffsetSeconds: -60,
      expiresInSeconds: -120,
    });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("token_expired");
    }
  });

  it("returns unknown_key_id when kid is missing from JWKS", async () => {
    const jwt = await makeJwt({
      issuer: "did:web:agecheck.me",
      ageTier: "21+",
      kid: "unknown-kid",
    });

    const result = await verifyAgeToken({
      jwt,
      expectedSession: "a4a1f09e-7da4-4ac7-bf7b-93825b4fce9e",
      config: {
        allowCustomIssuer: true,
        deploymentMode: "production",
        localJwks,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("unknown_key_id");
    }
  });
});
