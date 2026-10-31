import { request } from "undici";
import { randomUUID, createHmac, timingSafeEqual } from "node:crypto";

export interface StepUpRequest {
  agentId: string;
  principal: string;
  toolName: string;
  argumentsSummary: string;
  nonce?: string;
}

export type StepUpOutcome = "approved" | "denied" | "timeout";

/**
 * StepUpProvider pauses a tool call and waits for an explicit human
 * decision. v0.1 ships a webhook-based implementation. v0.2 should
 * implement this same interface using CIBA (Client-Initiated Backchannel
 * Authentication) against the upstream IdP, so the approval becomes a
 * verifiable authorization event rather than a bare webhook response.
 */
export interface StepUpProvider {
  requestApproval(req: StepUpRequest): Promise<StepUpOutcome>;
}

export class WebhookStepUpProvider implements StepUpProvider {
  constructor(
    private webhookUrl: string,
    private timeoutSeconds: number,
    private onTimeout: "deny" | "allow" = "deny",
    private webhookSecret?: string,
  ) {}

  async requestApproval(req: StepUpRequest): Promise<StepUpOutcome> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.timeoutSeconds * 1000,
    );

    const nonce = randomUUID();
    const payload: StepUpRequest = {
      ...req,
      nonce,
    };

    try {
      const res = await request(this.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      const body = (await res.body.json()) as { outcome?: string; signature?: string; nonce?: string };

      if (body.outcome === "approved") {
        if (this.webhookSecret) {
          if (body.nonce !== nonce) {
            return "denied";
          }
          if (!body.signature) {
            return "denied";
          }
          const expectedSig = createHmac("sha256", this.webhookSecret)
            .update(`${body.outcome}:${body.nonce}`)
            .digest("hex");

          const expectedBuf = Buffer.from(expectedSig);
          const actualBuf = Buffer.from(body.signature);

          if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
            return "denied";
          }
        }
        return "approved";
      }
      return "denied";
    } catch {
      return this.onTimeout === "allow" ? "approved" : "timeout";
    } finally {
      clearTimeout(timer);
    }
  }
}
