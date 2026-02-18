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

import type { JSONWebKeySet } from "jose";

export type DeploymentMode = "production" | "demo";

export interface AgeCheckVerifyConfig {
  allowCustomIssuer?: boolean;
  deploymentMode?: DeploymentMode;
  jwksUrl?: string;
  localJwks?: JSONWebKeySet;
  issuer?: string | string[];
  requiredAge?: number;
  leewaySeconds?: number;
}

export interface EasyAgeGateOptions {
  mode?: "modal" | "inline";
  autoOpen?: boolean;
  title?: string;
  subtitle?: string;
  waitingText?: string;
  successText?: string;
  errorPrefixText?: string;
  verifyButtonText?: string;
  cancelButtonText?: string;
  logoUrl?: string;
  logoWidth?: number;
  logoHeight?: number;
  modalMaxWidth?: number;
}

export interface GatePageOptions {
  redirect: string;
  easyAgeGate?: boolean;
  includeFields?: Array<"session" | "pidProvider" | "verificationMethod" | "loa">;
  agegateCdnUrl?: string;
  easyAgeGateCdnUrl?: string;
  easyAgeGateOptions?: EasyAgeGateOptions;
}

export interface GateEnforcementOptions {
  gatePath?: string;
  redirectTo?: string;
}

export interface VerifyInput {
  jwt: string;
  expectedSession?: string;
  requireSessionBinding?: boolean;
  config?: AgeCheckVerifyConfig;
}

export interface VerifySuccess {
  ok: true;
  claims: JwtClaims;
  ageTier: string;
  ageTierValue: number;
}

export interface VerifyFailure {
  ok: false;
  code: string;
  message: string;
  detail?: string;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

export interface AgeCheckGateConfig {
  headerName?: string;
  requiredValue?: string;
}

export interface AgeCheckSdkConfig {
  deploymentMode?: DeploymentMode;
  verify?: AgeCheckVerifyConfig;
  gate?: AgeCheckGateConfig;
  cookie: SignedCookieConfig;
}

export interface SignedCookieConfig {
  secret: string;
  cookieName?: string;
  ttlSeconds?: number;
}

export interface VerifiedCookiePayload {
  verified: true;
  exp: number;
  level: string;
}

export type VerificationType = "passkey" | "oid4vp" | "other";
export type EvidenceType = "webauthn_assertion" | "sd_jwt" | "zk_attestation" | "other";

export interface VerificationAssertion {
  provider: string;
  level: string;
  verified: true;
  verifiedAtUnix: number;
  assurance?: string;
  verificationType?: VerificationType;
  evidenceType?: EvidenceType;
  providerTransactionId?: string;
  loa?: string;
}

export interface ProviderAssertion {
  provider: string;
  verified: true;
  level: string;
  session: string;
  verifiedAtUnix: number;
  assurance?: string;
  verificationType?: VerificationType;
  evidenceType?: EvidenceType;
  providerTransactionId?: string;
  loa?: string;
}

export interface ExternalProviderAssertion {
  provider: string;
  verified: true;
  level: string;
  session: string;
  verifiedAtUnix?: number;
  assurance?: string;
  verificationType?: VerificationType;
  evidenceType?: EvidenceType;
  providerTransactionId?: string;
  loa?: string;
}

export interface ProviderFailure {
  verified: false;
  code: string;
  message: string;
  detail?: string;
}

export type ProviderVerificationResult = ExternalProviderAssertion | ProviderFailure;
export type NormalizedProviderVerificationResult = ProviderAssertion | ProviderFailure;

export interface VerifyAgeCheckCredentialInput {
  jwt: string;
  expectedSession: string;
  provider?: string;
  assurance?: string;
  verificationType?: VerificationType;
  evidenceType?: EvidenceType;
  providerTransactionId?: string;
  loa?: string;
}

export interface JwtClaims {
  iss?: unknown;
  sub?: unknown;
  vc?: unknown;
  exp?: unknown;
  nbf?: unknown;
  [key: string]: unknown;
}

export interface VcPayload {
  type?: unknown;
  credentialSubject?: unknown;
  [key: string]: unknown;
}

export interface VcSubject {
  id?: unknown;
  ageTier?: unknown;
  [key: string]: unknown;
}
