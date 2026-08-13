"use client";

import { useCallback, useMemo, useState } from "react";
import {
  createProvider,
  getFeed,
  listProviders,
  GatewayError,
  type FeedEntry,
  type Provider,
} from "@/lib/api";
import { usePolling } from "@/lib/usePolling";

/// Base Sepolia (84532). Testnet only — architecture.md §12.
const BASESCAN_TX = "https://sepolia.basescan.org/tx/";

/// Base units to a decimal USDC string. Six decimals, so "1000" reads as "0.001".
///
/// BigInt rather than Number: an amount is a U256 through NUMERIC and would lose precision as a
/// double. Written as `BigInt(…)` calls because tsconfig targets ES5, where the `1_000_000n`
/// literal syntax is not available.
const USDC_SCALE = BigInt(1000000);

function formatUsdc(baseUnits: string): string {
  const units = BigInt(baseUnits);
  const whole = units / USDC_SCALE;
  const fraction = (units % USDC_SCALE).toString().padStart(6, "0");
  return `${whole}.${fraction.replace(/0+$/, "").padEnd(2, "0")}`;
}

function shorten(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}

function age(timestamp: string): string {
  // The gateway serves `created_at::TEXT`, and Postgres renders that as
  // "2026-08-13 15:49:43.480207+00" — a space where ISO wants `T`, and a *two-digit* UTC offset.
  // `Date.parse` rejects both, so without this the column reads "—" on every row.
  const then = new Date(
    timestamp.replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00"),
  ).getTime();
  if (Number.isNaN(then)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

const EMPTY_FORM = {
  slug: "",
  upstream_url: "",
  price: "",
  payout_address: "",
  timeout_ms: "",
};

export default function ProviderPage() {
  const [form, setForm] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<GatewayError | null>(null);
  const [registered, setRegistered] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const providers = usePolling(listProviders, 2000);
  // Filtered client-side: `/v1/feed` has no provider parameter, and adding one would be a
  // Phase 7 endpoint change made during Phase 9. The window is the trade-off — a quiet
  // provider's rows can fall out once busier ones fill 200 entries.
  const feed = usePolling(useCallback(() => getFeed({ limit: 200 }), []), 2000);

  const rows: FeedEntry[] = useMemo(
    () => (feed.data ?? []).filter((row) => row.provider === selected),
    [feed.data, selected],
  );

  const providerList: Provider[] = providers.data ?? [];

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setRegistered(null);
    try {
      const created = await createProvider({
        slug: form.slug.trim(),
        upstream_url: form.upstream_url.trim(),
        price: form.price.trim(),
        payout_address: form.payout_address.trim(),
        ...(form.timeout_ms.trim()
          ? { timeout_ms: Number(form.timeout_ms) }
          : {}),
      });
      setRegistered(created.slug);
      setSelected(created.slug);
      setForm(EMPTY_FORM);
    } catch (caught) {
      setError(
        caught instanceof GatewayError
          ? caught
          : new GatewayError("network", String(caught), 0),
      );
    } finally {
      setSubmitting(false);
    }
  }

  const field = (
    name: keyof typeof EMPTY_FORM,
    label: string,
    placeholder: string,
    required = true,
  ) => (
    <label className="flex flex-col gap-1">
      <span className="mono text-[var(--muted)]">{label}</span>
      <input
        className="mono rounded border border-[var(--border)] bg-[var(--background)] px-2 py-1 outline-none focus:border-[var(--accent)]"
        value={form[name]}
        placeholder={placeholder}
        required={required}
        onChange={(e) => setForm({ ...form, [name]: e.target.value })}
      />
    </label>
  );

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h1 className="mono text-lg font-semibold">provider</h1>
        <p className="mt-1 text-[var(--muted)]">
          Wrap an endpoint, set a price per request, and watch agents pay for it.
        </p>
      </section>

      <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
        <h2 className="mono mb-3 text-[var(--muted)]">register an endpoint</h2>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            {field("slug", "slug", "geocode")}
            {field(
              "upstream_url",
              "upstream url",
              "https://nominatim.openstreetmap.org",
            )}
            {field("price", "price (USDC per request)", "0.001")}
            {field("payout_address", "payout address", "0x…")}
            {field("timeout_ms", "timeout ms (optional)", "30000", false)}
          </div>

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={submitting}
              className="mono rounded border border-[var(--accent)] px-3 py-1 text-[var(--accent)] disabled:opacity-50"
            >
              {submitting ? "registering…" : "register"}
            </button>
            {registered && (
              <span className="mono text-green-400">
                registered {registered}
              </span>
            )}
          </div>

          {/* The SSRF refusal from Task 4.2 surfaces here rather than in a console: it is the
              one registration error a provider is most likely to hit by accident, and the
              gateway's own message names the address that resolved. */}
          {error && (
            <p
              className={`mono rounded border px-2 py-1 ${
                error.code === "unsafe_upstream"
                  ? "border-red-500 bg-red-950/40 text-red-300"
                  : "border-[var(--border)] text-red-300"
              }`}
            >
              {error.code}: {error.message}
            </p>
          )}
        </form>
      </section>

      <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
        <h2 className="mono mb-2 text-[var(--muted)]">
          registered providers{providerList.length ? ` (${providerList.length})` : ""}
        </h2>
        {providers.loading ? (
          <p className="mono text-[var(--muted)]">loading…</p>
        ) : providerList.length === 0 ? (
          <p className="mono text-[var(--muted)]">
            No providers yet. Register one above — slug, upstream URL, a price in
            USDC and a payout address are all it takes.
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {providerList.map((provider) => (
              <button
                key={provider.slug}
                onClick={() => setSelected(provider.slug)}
                className={`mono rounded border px-2 py-1 ${
                  selected === provider.slug
                    ? "border-[var(--accent)] text-[var(--accent)]"
                    : "border-[var(--border)] text-[var(--muted)]"
                }`}
              >
                {provider.slug}{" "}
                <span className="opacity-60">
                  {formatUsdc(provider.price_wei)}
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
        <h2 className="mono mb-2 text-[var(--muted)]">
          request log{selected ? ` · ${selected}` : ""}
        </h2>

        {!selected ? (
          <p className="mono text-[var(--muted)]">
            Select a provider above to see its paid requests.
          </p>
        ) : rows.length === 0 ? (
          <p className="mono text-[var(--muted)]">
            No paid requests yet for {selected}. Point an agent at{" "}
            <span className="text-[var(--foreground)]">
              /v1/proxy/{selected}/…
            </span>{" "}
            — it will get a 402, pay it, and the charge appears here within 2s.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="mono w-full text-left">
              <thead className="text-[var(--muted)]">
                <tr>
                  <th className="py-1 pr-4 font-normal">payer</th>
                  <th className="py-1 pr-4 font-normal">upstream</th>
                  <th className="py-1 pr-4 font-normal">amount</th>
                  <th className="py-1 pr-4 font-normal">status</th>
                  <th className="py-1 pr-4 font-normal">tx</th>
                  <th className="py-1 font-normal">age</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={`${row.payer}-${row.timestamp}`}
                    className="border-t border-[var(--border)]"
                  >
                    <td className="py-1 pr-4" title={row.payer}>
                      {shorten(row.payer)}
                    </td>
                    <td
                      className={`py-1 pr-4 ${
                        row.upstream_status && row.upstream_status >= 400
                          ? "text-red-400"
                          : ""
                      }`}
                    >
                      {row.upstream_status ?? "—"}
                    </td>
                    <td className="py-1 pr-4">{formatUsdc(row.amount_wei)}</td>
                    <td className="py-1 pr-4 text-[var(--muted)]">
                      {row.status}
                    </td>
                    <td className="py-1 pr-4">
                      {row.tx_hash ? (
                        <a
                          className="text-[var(--accent)]"
                          href={`${BASESCAN_TX}${row.tx_hash}`}
                          target="_blank"
                          rel="noreferrer"
                          title={row.tx_hash}
                        >
                          {shorten(row.tx_hash)}
                        </a>
                      ) : (
                        <span className="text-[var(--muted)]">—</span>
                      )}
                    </td>
                    <td className="py-1">{age(row.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {feed.error && (
          <p className="mono mt-2 text-red-400">
            feed unreachable — {feed.error.message}
          </p>
        )}
      </section>
    </div>
  );
}
