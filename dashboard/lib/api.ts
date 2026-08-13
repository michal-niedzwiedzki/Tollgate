// Typed access to the gateway. Task 9.1.
//
// Every type here mirrors a Rust handler's response shape exactly, so the field names are the
// gateway's and not a nicer-looking guess: `price_wei` and `amount_wei` are decimal strings of
// base units because they are U256 through NUMERIC and would lose precision as a JS number, and
// every address and hash is a 0x string.

/// The shared error body every endpoint returns on failure, defined once in
/// `tollgate-core/src/error.rs` (Task 1.3).
export interface ErrorBody {
  error: { code: string; message: string };
}

/// `GET /v1/providers`, `GET /v1/providers/{slug}`, and the 201 body of `POST /v1/providers`.
export interface Provider {
  slug: string;
  upstream_url: string;
  /// Base units. 6 decimals for USDC, so "1000" is 0.001 USDC.
  price_wei: string;
  max_price_wei: string | null;
  scheme: string;
  payout_address: string;
  timeout_ms: number;
}

/// The `POST /v1/providers` request body. `price` is a decimal USDC string ("0.001"), converted
/// to base units server-side.
export interface CreateProviderRequest {
  slug: string;
  upstream_url: string;
  price: string;
  payout_address: string;
  scheme?: string;
  timeout_ms?: number;
}

/// One row of `GET /v1/feed`. Excludes `voided` charges; `status` is present so a settled charge
/// is distinguishable from a queued one without inferring it from `tx_hash` being null.
export interface FeedEntry {
  payer: string;
  provider: string | null;
  amount_wei: string;
  upstream_status: number | null;
  tx_hash: string | null;
  status: string;
  /// ISO-8601. Pass the newest one back as `since` to poll for only what has landed since.
  timestamp: string;
}

/// `GET /v1/stats`. Every field is nullable because an unobserved stage or an empty ledger
/// returns JSON null rather than a fabricated zero.
///
/// `gateway_*` is Tollgate's own added latency and `upstream_p50` is the upstream hop. They are
/// separate fields and must never be summed or shown as one number (prd.md §8).
export interface Stats {
  gateway_p50: number | null;
  gateway_p99: number | null;
  upstream_p50: number | null;
  batch_size: number | null;
  gas_per_batch: number | null;
  gas_per_charge: number | null;
  queue_depth: number;
  mean_queued_to_settled_seconds: number | null;
}

/// One capability in the delegation tree, children nested beneath it.
///
/// `spent` already includes everything this node's descendants spent — every charge decrements
/// every level of its chain (architecture.md §5.2) — so summing children would double-count.
/// These three are decimal USDC strings ("0.42"), not base units.
export interface ExpenseNode {
  hash: string;
  subject: string;
  depth: number;
  spent: string;
  max_total: string;
  remaining: string;
  /// Null when this capability inherits its parent's allowlist, and on a payer-level node,
  /// which has no capability row at all. Null is not an empty allowlist.
  allowlist: string[] | null;
  /// Unix seconds. Null on a payer-level node.
  expiry: number | null;
  /// RFC 3339, or null if this capability has not been revoked.
  revoked_at: string | null;
  children: ExpenseNode[];
}

export interface ExpenseCharge {
  nonce: string;
  provider: string | null;
  amount: string;
  upstream_status: number | null;
  status: string;
  tx_hash: string | null;
  settled_at: string | null;
  receipt_sig: string | null;
}

/// `GET /v1/expense-report`. `generated_at` and `signature` sit outside the signed body: a
/// verifier strips exactly those two keys, re-serialises the rest as compact JSON with sorted
/// keys, and hashes that (NOTES.md D15).
export interface ExpenseReport {
  root: string;
  total_spent: string;
  failed_count: number;
  nodes: ExpenseNode[];
  charges: ExpenseCharge[];
  generated_at: number;
  signature: string;
}

/// `GET /v1/receipts/{nonce}`. This is the exact body the signature covers, plus `tx_hash`,
/// which is null until the settler lands the batch.
export interface Receipt {
  nonce: string;
  payer: string;
  capability_hash: string;
  provider_slug: string;
  /// Base units, as a string.
  amount: string;
  upstream_status: number;
  timestamp: number;
  signature: string;
  tx_hash: string | null;
}

const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

/// Thrown for any non-2xx response, carrying the gateway's own error code so a caller can match
/// on it — `unsafe_upstream` on the provider form, for instance — rather than on message text.
export class GatewayError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "GatewayError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${GATEWAY_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
    // The dashboard always wants what the gateway has right now, never what Next cached.
    cache: "no-store",
  });

  if (!response.ok) {
    // A 500 from a panicking handler, or a proxy in front of it, need not be JSON at all.
    const body = (await response.json().catch(() => null)) as ErrorBody | null;
    throw new GatewayError(
      body?.error?.code ?? "unknown",
      body?.error?.message ?? `${response.status} ${response.statusText}`,
      response.status,
    );
  }

  return (await response.json()) as T;
}

export function listProviders(): Promise<Provider[]> {
  return request<Provider[]>("/v1/providers");
}

export function getProvider(slug: string): Promise<Provider> {
  return request<Provider>(`/v1/providers/${encodeURIComponent(slug)}`);
}

export function createProvider(body: CreateProviderRequest): Promise<Provider> {
  return request<Provider>("/v1/providers", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getFeed(options: { limit?: number; since?: string } = {}) {
  const params = new URLSearchParams();
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.since !== undefined) params.set("since", options.since);
  const query = params.toString();
  return request<FeedEntry[]>(`/v1/feed${query ? `?${query}` : ""}`);
}

export function getStats(): Promise<Stats> {
  return request<Stats>("/v1/stats");
}

/// The report is rooted at a capability, or at a payer for the no-delegation case (NOTES.md D1).
export function getExpenseReport(
  root: { capability: string } | { payer: string },
): Promise<ExpenseReport> {
  const params = new URLSearchParams(
    "capability" in root
      ? { capability: root.capability }
      : { payer: root.payer },
  );
  return request<ExpenseReport>(`/v1/expense-report?${params.toString()}`);
}

export function getReceipt(nonce: string): Promise<Receipt> {
  return request<Receipt>(`/v1/receipts/${encodeURIComponent(nonce)}`);
}
