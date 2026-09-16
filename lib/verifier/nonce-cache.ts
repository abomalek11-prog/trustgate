/**
 * Verifier-local memory of consumed nonces. Combined with the request's
 * issuedAt/expiresAt this defeats replay: a nonce only needs to be remembered
 * until the request that carried it could no longer be fresh anyway.
 */
export interface NonceRecord {
  firstSeenAt: number;
  expiresAt: number;
}

export class NonceCache {
  private seen = new Map<string, NonceRecord>();

  get(nonce: string): NonceRecord | undefined {
    return this.seen.get(nonce);
  }

  has(nonce: string): boolean {
    return this.seen.has(nonce);
  }

  add(nonce: string, nowMs: number, ttlMs: number): void {
    if (!this.seen.has(nonce)) this.seen.set(nonce, { firstSeenAt: nowMs, expiresAt: nowMs + ttlMs });
  }

  /** Drop records whose freshness window has passed (they can no longer be replayed). */
  prune(nowMs: number): void {
    for (const [k, v] of this.seen) if (v.expiresAt <= nowMs) this.seen.delete(k);
  }

  get size(): number {
    return this.seen.size;
  }

  entries(): Array<[string, NonceRecord]> {
    return Array.from(this.seen.entries());
  }

  clear(): void {
    this.seen.clear();
  }
}
