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

import { createVerifiedCookieValue, createVerifiedCookieValueFromLevel, formatSetCookieHeader, verifySignedCookieValue } from "./cookie.js";
import { AgeCheckError, ErrorCode } from "./errors.js";
import { isGateRequired } from "./gate.js";
import type {
  AgeCheckVerifyConfig,
  DeploymentMode,
  AgeCheckSdkConfig,
  EasyAgeGateOptions,
  GateEnforcementOptions,
  GatePageOptions,
  JwtClaims,
  VerificationAssertion,
  VerifyResult,
} from "./types.js";
import { verifyAgeToken } from "./verify.js";

const DEFAULT_INCLUDE: Array<"session" | "pidProvider" | "verificationMethod" | "loa"> = [
  "session",
  "pidProvider",
  "verificationMethod",
  "loa",
];

function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const pair of header.split(";")) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key.length > 0) out[key] = value;
  }
  return out;
}

function normalizeRedirect(raw: string): string {
  try {
    const parsed = new URL(raw, "https://example.invalid");
    if (parsed.origin !== "https://example.invalid") {
      return "/";
    }
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return "/";
  }
}

function normalizeGatePath(raw: string): string {
  const normalized = normalizeRedirect(raw);
  return normalized.startsWith("/") ? normalized : "/";
}

function escJson<T>(value: T): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export class AgeCheckSdk {
  private readonly cfg: AgeCheckSdkConfig;
  private readonly deploymentMode: DeploymentMode;

  public constructor(config: AgeCheckSdkConfig) {
    if (!config || typeof config !== "object") {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "AgeCheckSdk requires configuration.");
    }
    const deploymentMode = config.deploymentMode ?? "production";
    if (deploymentMode !== "production" && deploymentMode !== "demo") {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "deploymentMode must be production or demo.");
    }
    this.deploymentMode = deploymentMode;
    this.cfg = config;
  }

  public shouldGate(request: Request): boolean {
    if (this.deploymentMode === "demo") {
      return true;
    }
    return isGateRequired(request.headers, this.cfg.gate);
  }

  public async getVerifiedCookiePayload(request: Request): Promise<JwtClaims | null> {
    const cookieName = this.cfg.cookie.cookieName ?? "agecheck_verified";
    const cookies = parseCookies(request.headers.get("cookie"));
    const value = cookies[cookieName];
    if (typeof value !== "string") {
      return null;
    }

    const verified = await verifySignedCookieValue(value, this.cfg.cookie);
    if (verified === null) {
      return null;
    }

    return {
      exp: verified.exp,
      vc: {
        credentialSubject: {
          ageTier: verified.level,
        },
      },
    };
  }

  public async verifyToken(jwt: string, expectedSession: string | undefined): Promise<VerifyResult> {
    const verifyConfig: AgeCheckVerifyConfig = {
      ...(this.cfg.verify ?? {}),
      deploymentMode: this.deploymentMode,
    };

    const input: {
      jwt: string;
      requireSessionBinding: boolean;
      config?: AgeCheckVerifyConfig;
      expectedSession?: string;
    } = {
      jwt,
      requireSessionBinding: true,
    };
    input.config = verifyConfig;
    if (typeof expectedSession === "string") {
      input.expectedSession = expectedSession;
    }
    return verifyAgeToken(input);
  }

  public async verifyTokenAndBuildSetCookie(
    jwt: string,
    expectedSession: string | undefined,
  ): Promise<{ verify: VerifyResult; setCookie?: string; assertion?: VerificationAssertion }> {
    const verify = await this.verifyToken(jwt, expectedSession);
    if (!verify.ok) {
      return { verify };
    }

    const now = Math.floor(Date.now() / 1000);
    const assertion: VerificationAssertion = {
      provider: "agecheck",
      level: verify.ageTier,
      verified: true,
      verifiedAtUnix: now,
      assurance: "passkey",
    };
    const created = await createVerifiedCookieValue(verify.claims, this.cfg.cookie);
    const maxAgeSeconds = this.cfg.cookie.ttlSeconds ?? 86400;
    const setCookie = formatSetCookieHeader(created.cookieName, created.cookieValue, created.payload.exp, maxAgeSeconds);
    return { verify, setCookie, assertion };
  }

  public async buildSetCookieFromAssertion(assertion: VerificationAssertion): Promise<string> {
    if (assertion.verified !== true) {
      throw new AgeCheckError(ErrorCode.INVALID_INPUT, "verification assertion must be verified.");
    }
    const created = await createVerifiedCookieValueFromLevel(assertion.level, this.cfg.cookie);
    const maxAgeSeconds = this.cfg.cookie.ttlSeconds ?? 86400;
    return formatSetCookieHeader(created.cookieName, created.cookieValue, created.payload.exp, maxAgeSeconds);
  }

  public async requireVerifiedOrRedirect(
    request: Request,
    options: GateEnforcementOptions = {},
  ): Promise<Response | null> {
    if (!this.shouldGate(request)) {
      return null;
    }

    const verified = await this.getVerifiedCookiePayload(request);
    if (verified !== null) {
      return null;
    }

    const requestUrl = new URL(request.url);
    const gatePath = normalizeGatePath(options.gatePath ?? "/ageverify");
    const redirectTarget =
      typeof options.redirectTo === "string" && options.redirectTo.length > 0
        ? normalizeRedirect(options.redirectTo)
        : `${requestUrl.pathname}${requestUrl.search}`;

    const gateUrl = new URL(gatePath, requestUrl.origin);
    gateUrl.searchParams.set("redirect", redirectTarget);
    return Response.redirect(gateUrl.toString(), 302);
  }

  public renderGatePage(options: GatePageOptions): string {
    const redirect = normalizeRedirect(options.redirect);
    const includeFields = options.includeFields ?? DEFAULT_INCLUDE;
    const easyAgeGate = options.easyAgeGate ?? false;
    const agegateCdn = options.agegateCdnUrl ?? "https://cdn.agecheck.me/agegate/v1/agegate.min.js";
    const easyCdn = options.easyAgeGateCdnUrl ?? "https://cdn.agecheck.me/agegate/v1/easy-agegate.min.js";

    if (easyAgeGate) {
      const easyOptions: EasyAgeGateOptions & {
        include: Array<"session" | "pidProvider" | "verificationMethod" | "loa">;
      } = {
        ...(options.easyAgeGateOptions ?? {}),
        include: includeFields,
      };

      const easyOptionsJson = escJson(easyOptions);

      return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>AgeCheck Gate</title>
</head>
<body>
  <script src="${easyCdn}"></script>
  <script>
    const redirect = ${escJson(redirect)};

    const onSuccess = async (jwt, payload) => {
      const res = await fetch('/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jwt, payload, redirect })
      });
      const out = await res.json();
      if (out.verified && typeof out.redirect === 'string') {
        window.location.assign(out.redirect);
      }
    };

    const onFailure = (err) => {
      console.error('AgeCheck verification failed', err);
    };

    const easyConfig = ${easyOptionsJson};
    easyConfig.onSuccess = onSuccess;
    easyConfig.onFailure = onFailure;
    window.AgeCheck.AgeGate.init(easyConfig);
  </script>
</body>
</html>`;
    }

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>AgeCheck Gate</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e5e7eb;padding:16px}
    main{max-width:420px;width:100%;background:#111827;border:1px solid #374151;border-radius:14px;padding:20px}
    h1{font-size:22px;margin:0 0 8px}
    p{margin:0 0 12px;color:#cbd5e1}
    button{width:100%;padding:12px;border:0;border-radius:10px;background:#7c3aed;color:white;font-weight:700;cursor:pointer}
    #status{margin-top:12px;font-size:14px;color:#94a3b8}
  </style>
</head>
<body>
  <main>
    <h1>Age Restricted Content</h1>
    <p>Please confirm your age anonymously using AgeCheck.me.</p>
    <button id="verify">Verify Now</button>
    <p id="status"></p>
  </main>
  <script src="${agegateCdn}"></script>
  <script>
    const status = document.getElementById('status');
    const redirect = ${escJson(redirect)};

    document.getElementById('verify').addEventListener('click', () => {
      const session = crypto.randomUUID();
      status.textContent = 'Opening secure verification...';
      window.AgeCheck.launchAgeGate({
        session,
        include: ${escJson(includeFields)},
        onSuccess: async (jwt, payload) => {
          const res = await fetch('/verify', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jwt, payload, redirect })
          });
          const out = await res.json();
          if (out.verified && typeof out.redirect === 'string') {
            window.location.assign(out.redirect);
            return;
          }
          status.textContent = out.error || 'Verification failed.';
        },
        onFailure: (err) => {
          status.textContent = (err && err.message) ? err.message : 'Verification failed.';
        }
      });
    });
  </script>
</body>
</html>`;
  }
}
