import { request } from "undici";

export interface StepUpRequest {
  agentId: string;
  principal: string;
  toolName: string;
  argumentsSummary: string;
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
  ) {}

  async requestApproval(req: StepUpRequest): Promise<StepUpOutcome> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.timeoutSeconds * 1000,
    );

    try {
      const res = await request(this.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
        signal: controller.signal,
      });
      const body = (await res.body.json()) as { outcome?: string };
      if (body.outcome === "approved") return "approved";
      return "denied";
    } catch {
      return this.onTimeout === "allow" ? "approved" : "timeout";
    } finally {
      clearTimeout(timer);
    }
  }
}
