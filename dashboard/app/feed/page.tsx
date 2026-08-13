"use client";

import { useEffect, useRef, useState } from "react";
import { getFeed, getStats, type FeedEntry, type Stats } from "@/lib/api";
import { usePolling } from "@/lib/usePolling";

const BASESCAN_TX = "https://sepolia.basescan.org/tx/";

/// Display assumptions for the USD figure, not a live quote. Defaults match the README's
/// "Settlement cost" section — Base's gas price at the time it was measured — so the panel and
/// that section agree by construction. architecture.md §7.2: do not build a gas oracle.
const GAS_PRICE_GWEI = Number(process.env.NEXT_PUBLIC_GAS_PRICE_GWEI ?? "0.006");
const ETH_USD = Number(process.env.NEXT_PUBLIC_ETH_USD ?? "3000");

function shorten(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}

const USDC_SCALE = BigInt(1000000);

function formatUsdc(baseUnits: string): string {
  const units = BigInt(baseUnits);
  const whole = units / USDC_SCALE;
  const fraction = (units % USDC_SCALE).toString().padStart(6, "0");
  return `${whole}.${fraction.replace(/0+$/, "").padEnd(2, "0")}`;
}

/// Postgres renders `created_at::TEXT` as "2026-08-13 15:49:43.480207+00" — a space where ISO
/// wants `T`, and a two-digit UTC offset. `Date.parse` rejects both.
function parseTimestamp(raw: string): number {
  return new Date(
    raw.replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00"),
  ).getTime();
}

function age(timestamp: string): string {
  const then = parseTimestamp(timestamp);
  if (Number.isNaN(then)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

/// Seconds to milliseconds. An unobserved stage is null from `/v1/stats` and stays "—" here
/// rather than becoming a fabricated zero.
function ms(seconds: number | null): string {
  return seconds === null ? "—" : `${(seconds * 1000).toFixed(2)} ms`;
}

/// The feed has no nonce, so a row is identified by payer + timestamp — unique in practice
/// because one payer cannot land two charges in the same microsecond.
function rowKey(row: FeedEntry): string {
  return `${row.payer}-${row.timestamp}`;
}

function Stat({
  label,
  value,
  hint,
  emphasis,
}: {
  label: string;
  value: string;
  hint?: string;
  emphasis?: "good" | "bad";
}) {
  return (
    <div>
      <div className="mono text-[var(--muted)]">{label}</div>
      <div
        className={`mono text-base ${
          emphasis === "good"
            ? "text-green-400"
            : emphasis === "bad"
              ? "text-red-400"
              : ""
        }`}
      >
        {value}
      </div>
      {hint && <div className="mono text-[var(--muted)]">{hint}</div>}
    </div>
  );
}

function LatencyPanel({ stats }: { stats: Stats | null }) {
  return (
    <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
      <h2 className="mono mb-2 text-[var(--muted)]">latency</h2>
      {/* prd.md §8 warns these will be conflated if shown together, so they are labelled by
          who pays for them and never summed into one number. */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Stat
          label="Tollgate added p50"
          value={ms(stats?.gateway_p50 ?? null)}
          hint="target < 15 ms"
          emphasis={
            stats?.gateway_p50 == null
              ? undefined
              : stats.gateway_p50 * 1000 < 15
                ? "good"
                : "bad"
          }
        />
        <Stat
          label="Tollgate added p99"
          value={ms(stats?.gateway_p99 ?? null)}
          hint="target < 50 ms"
          emphasis={
            stats?.gateway_p99 == null
              ? undefined
              : stats.gateway_p99 * 1000 < 50
                ? "good"
                : "bad"
          }
        />
        <Stat
          label="upstream p50"
          value={ms(stats?.upstream_p50 ?? null)}
          hint="the caller was paying this anyway"
        />
      </div>
    </section>
  );
}

function SettlementPanel({ stats }: { stats: Stats | null }) {
  const gasPerCharge = stats?.gas_per_charge ?? null;
  const costPerCharge =
    gasPerCharge === null
      ? null
      : gasPerCharge * GAS_PRICE_GWEI * 1e-9 * ETH_USD;

  return (
    <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
      <h2 className="mono mb-2 text-[var(--muted)]">settlement</h2>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <Stat
          label="last batch"
          value={stats?.batch_size?.toLocaleString() ?? "—"}
          hint="charges"
        />
        <Stat
          label="gas used"
          value={stats?.gas_per_batch?.toLocaleString() ?? "—"}
          hint="that batch"
        />
        <Stat
          label="gas / charge"
          value={gasPerCharge?.toLocaleString() ?? "—"}
        />
        <Stat
          label="cost / charge"
          value={costPerCharge === null ? "—" : `$${costPerCharge.toFixed(5)}`}
          hint={
            costPerCharge === null
              ? "no settled batch yet"
              : costPerCharge < 0.001
                ? "under $0.001 ✓"
                : "over $0.001"
          }
          emphasis={
            costPerCharge === null
              ? undefined
              : costPerCharge < 0.001
                ? "good"
                : "bad"
          }
        />
        <Stat
          label="queue depth"
          value={stats?.queue_depth?.toLocaleString() ?? "—"}
          hint="awaiting settlement"
        />
      </div>
      <p className="mono mt-2 text-[var(--muted)]">
        cost assumes {GAS_PRICE_GWEI} gwei and ETH at $
        {ETH_USD.toLocaleString()} — a stated assumption, not a live quote
      </p>
    </section>
  );
}

export default function FeedPage() {
  const feed = usePolling(getFeed, 1000);
  const stats = usePolling(getStats, 2000);

  // Rows seen at least once. Everything present on the first successful poll is seeded without
  // highlighting, so opening the page does not flash the entire backlog.
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());

  useEffect(() => {
    const rows = feed.data;
    if (!rows) return;

    if (seen.current === null) {
      seen.current = new Set(rows.map(rowKey));
      return;
    }

    const added = rows.map(rowKey).filter((key) => !seen.current!.has(key));
    if (added.length === 0) return;
    added.forEach((key) => seen.current!.add(key));

    // Copy-then-add rather than spreading: tsconfig targets ES5, where iterating a Set needs
    // downlevelIteration.
    setFresh((previous) => {
      const next = new Set(previous);
      added.forEach((key) => next.add(key));
      return next;
    });
    const handle = setTimeout(() => {
      setFresh((previous) => {
        const next = new Set(previous);
        added.forEach((key) => next.delete(key));
        return next;
      });
    }, 1500);
    return () => clearTimeout(handle);
  }, [feed.data]);

  const rows = feed.data ?? [];

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h1 className="mono text-lg font-semibold">feed</h1>
        <p className="mt-1 text-[var(--muted)]">
          Every charge as it lands, with what Tollgate added to the request and
          what settlement costs.
        </p>
      </section>

      <LatencyPanel stats={stats.data} />
      <SettlementPanel stats={stats.data} />

      <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
        <h2 className="mono mb-2 text-[var(--muted)]">
          charges ({rows.length})
        </h2>
        {feed.error && (
          <p className="mono mb-2 text-red-400">
            feed unreachable — {feed.error.message}
          </p>
        )}
        {rows.length === 0 ? (
          <p className="mono text-[var(--muted)]">
            No charges yet. Pay for a request through the gateway and it appears
            here within a second.
          </p>
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            <table className="mono w-full text-left">
              <thead className="sticky top-0 bg-[var(--panel)] text-[var(--muted)]">
                <tr>
                  <th className="py-1 pr-4 font-normal">payer</th>
                  <th className="py-1 pr-4 font-normal">provider</th>
                  <th className="py-1 pr-4 font-normal">amount</th>
                  <th className="py-1 pr-4 font-normal">upstream</th>
                  <th className="py-1 pr-4 font-normal">status</th>
                  <th className="py-1 pr-4 font-normal">tx</th>
                  <th className="py-1 font-normal">age</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const key = rowKey(row);
                  return (
                    <tr
                      key={key}
                      // New rows enter at the top with a brief highlight that fades, so a
                      // reader can see the feed moving without watching the clock.
                      className={`border-t border-[var(--border)] transition-colors duration-1000 ${
                        fresh.has(key) ? "bg-green-500/20" : ""
                      }`}
                    >
                      <td className="py-1 pr-4" title={row.payer}>
                        {shorten(row.payer)}
                      </td>
                      <td className="py-1 pr-4">{row.provider ?? "—"}</td>
                      <td className="py-1 pr-4">
                        {formatUsdc(row.amount_wei)}
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
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
