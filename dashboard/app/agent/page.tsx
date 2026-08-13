"use client";

import { Suspense, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import {
  getExpenseReport,
  type ExpenseCharge,
  type ExpenseNode,
} from "@/lib/api";
import { usePolling } from "@/lib/usePolling";

const BASESCAN_TX = "https://sepolia.basescan.org/tx/";

function shorten(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}

/// A node is capped when its cumulative spend has reached its ceiling. Compared in base units
/// rather than as floats: these are decimal USDC strings and "0.30" vs "0.3" must not decide it.
function toBaseUnits(usdc: string): number {
  const [whole, fraction = ""] = usdc.split(".");
  return Number(whole) * 1_000_000 + Number(fraction.padEnd(6, "0").slice(0, 6));
}

function isCapped(node: ExpenseNode): boolean {
  return toBaseUnits(node.spent) >= toBaseUnits(node.max_total);
}

function percentSpent(node: ExpenseNode): number {
  const max = toBaseUnits(node.max_total);
  if (max <= 0) return 0;
  return Math.min(100, (toBaseUnits(node.spent) / max) * 100);
}

function expiryLabel(expiry: number | null): string | null {
  if (expiry === null) return null;
  const remaining = expiry * 1000 - Date.now();
  if (remaining <= 0) return "expired";
  const minutes = Math.floor(remaining / 60000);
  if (minutes < 60) return `expires in ${minutes}m`;
  return `expires in ${Math.floor(minutes / 60)}h`;
}

/// One capability. The card carries everything a supervisor needs to answer "why did this
/// worker stop": who may spend, where, until when, and how much is left.
function NodeCard({ node }: { node: ExpenseNode }) {
  const capped = isCapped(node);
  const revoked = node.revoked_at !== null;
  const percent = percentSpent(node);

  return (
    <div
      className={`rounded border p-2 ${
        capped
          ? "border-red-500 bg-red-950/30"
          : "border-[var(--border)] bg-[var(--panel)]"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        {/* A revoked capability is struck through wherever it appears: the chain is refused at
            the gateway regardless of how much budget the bar still shows. */}
        <span
          className={`mono font-semibold ${revoked ? "line-through opacity-60" : ""}`}
          title={node.hash}
        >
          {shorten(node.subject)}
        </span>
        <span className="mono text-[var(--muted)]">depth {node.depth}</span>
        {capped && (
          <span className="mono rounded bg-red-500/20 px-1 text-red-300">
            capped
          </span>
        )}
        {revoked && (
          <span className="mono rounded bg-[var(--border)] px-1 text-[var(--muted)]">
            revoked
          </span>
        )}
      </div>

      <div className="mono mt-1 flex flex-wrap gap-x-3 text-[var(--muted)]">
        <span>
          {node.allowlist === null ? "allowlist: inherited" : `allowlist: ${node.allowlist.join(", ") || "none"}`}
        </span>
        {expiryLabel(node.expiry) && <span>{expiryLabel(node.expiry)}</span>}
      </div>

      {/* The bar transitions over the poll interval rather than jumping, so a spending worker
          reads as draining. This is the screen prd.md §9 step 3 is about. */}
      <div className="mt-2 h-2 w-full overflow-hidden rounded bg-[var(--border)]">
        <div
          className={`h-full transition-[width] duration-1000 ease-linear ${
            capped ? "bg-red-500" : "bg-green-500"
          }`}
          style={{ width: `${percent}%` }}
        />
      </div>
      <div className="mono mt-1 text-[var(--muted)]">
        {node.spent} / {node.max_total} spent ·{" "}
        <span className={capped ? "text-red-300" : "text-[var(--foreground)]"}>
          {node.remaining} left
        </span>
      </div>
    </div>
  );
}

/// Nested children with connector lines, so the delegation chain reads as a tree rather than
/// an indented list.
function NodeTree({ node }: { node: ExpenseNode }) {
  return (
    <li className="relative pl-4 before:absolute before:left-0 before:top-4 before:h-px before:w-3 before:bg-[var(--border)]">
      <NodeCard node={node} />
      {node.children.length > 0 && (
        <ul className="ml-3 border-l border-[var(--border)]">
          {node.children.map((child) => (
            <NodeTree key={child.hash} node={child} />
          ))}
        </ul>
      )}
    </li>
  );
}

function ChargeList({ charges }: { charges: ExpenseCharge[] }) {
  if (charges.length === 0) {
    return (
      <p className="mono text-[var(--muted)]">
        No charges under this subtree yet.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="mono w-full text-left">
        <thead className="text-[var(--muted)]">
          <tr>
            <th className="py-1 pr-4 font-normal">nonce</th>
            <th className="py-1 pr-4 font-normal">provider</th>
            <th className="py-1 pr-4 font-normal">amount</th>
            <th className="py-1 pr-4 font-normal">upstream</th>
            <th className="py-1 pr-4 font-normal">status</th>
            <th className="py-1 font-normal">tx</th>
          </tr>
        </thead>
        <tbody>
          {charges.map((charge) => (
            <tr key={charge.nonce} className="border-t border-[var(--border)]">
              <td className="py-1 pr-4" title={charge.nonce}>
                {shorten(charge.nonce)}
              </td>
              <td className="py-1 pr-4">{charge.provider ?? "—"}</td>
              <td className="py-1 pr-4">{charge.amount}</td>
              <td className="py-1 pr-4">{charge.upstream_status ?? "—"}</td>
              <td className="py-1 pr-4 text-[var(--muted)]">{charge.status}</td>
              <td className="py-1">
                {charge.tx_hash ? (
                  <a
                    className="text-[var(--accent)]"
                    href={`${BASESCAN_TX}${charge.tx_hash}`}
                    target="_blank"
                    rel="noreferrer"
                    title={charge.tx_hash}
                  >
                    {shorten(charge.tx_hash)}
                  </a>
                ) : (
                  <span className="text-[var(--muted)]">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AgentView() {
  const params = useSearchParams();
  const capability = params.get("capability");
  const payer = params.get("payer");

  const root = capability
    ? { capability }
    : payer
      ? { payer }
      : null;

  const report = usePolling(
    useCallback(
      () =>
        root
          ? getExpenseReport(root)
          : Promise.reject(new Error("no root selected")),
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [capability, payer],
    ),
    1000,
    [capability, payer],
  );

  if (!root) {
    return (
      <div className="flex flex-col gap-2">
        <h1 className="mono text-lg font-semibold">agent</h1>
        <p className="mono text-[var(--muted)]">
          Pass a root to watch:{" "}
          <span className="text-[var(--foreground)]">
            /agent?capability=0x…
          </span>{" "}
          for a delegation tree, or{" "}
          <span className="text-[var(--foreground)]">/agent?payer=0x…</span> for
          a payer-level budget.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h1 className="mono text-lg font-semibold">agent</h1>
        <p className="mt-1 text-[var(--muted)]">
          Every charge draws down every capability in the chain, so a
          supervisor&apos;s bar drains as its workers spend.
        </p>
      </section>

      {report.error && (
        <p className="mono rounded border border-red-500 bg-red-950/40 px-2 py-1 text-red-300">
          {report.error.message}
        </p>
      )}

      {report.loading ? (
        <p className="mono text-[var(--muted)]">loading…</p>
      ) : report.data ? (
        <>
          <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
            <h2 className="mono mb-2 text-[var(--muted)]">
              delegation tree · total spent {report.data.total_spent}
              {report.data.failed_count > 0 &&
                ` · ${report.data.failed_count} failed`}
            </h2>
            <ul>
              {report.data.nodes.map((node) => (
                <NodeTree key={node.hash} node={node} />
              ))}
            </ul>
          </section>

          <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
            <h2 className="mono mb-2 text-[var(--muted)]">
              charges ({report.data.charges.length})
            </h2>
            <ChargeList charges={report.data.charges} />
          </section>
        </>
      ) : null}
    </div>
  );
}

export default function AgentPage() {
  // `useSearchParams` needs a Suspense boundary to prerender in the App Router.
  return (
    <Suspense
      fallback={<p className="mono text-[var(--muted)]">loading…</p>}
    >
      <AgentView />
    </Suspense>
  );
}
