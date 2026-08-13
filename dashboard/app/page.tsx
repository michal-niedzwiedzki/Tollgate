"use client";

import Link from "next/link";
import { getStats } from "@/lib/api";
import { usePolling } from "@/lib/usePolling";

/// The landing view. Deliberately thin: it exists to prove the shell works end to end — the API
/// client reaches the gateway cross-origin and the polling hook refreshes — and to point at the
/// three views. The panels themselves belong to Tasks 9.2, 9.3 and 9.4.
export default function Home() {
  const { data, error, loading } = usePolling(getStats, 5000);

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h1 className="mono text-lg font-semibold">tollgate dashboard</h1>
        <p className="mt-1 text-[var(--muted)]">
          Spend control and provable receipts for agent API payments, on x402.
        </p>
      </section>

      <section className="rounded border border-[var(--border)] bg-[var(--panel)] p-3">
        <h2 className="mono text-[var(--muted)]">gateway</h2>
        {loading ? (
          <p className="mono mt-1">connecting…</p>
        ) : error ? (
          <p className="mono mt-1 text-red-400">unreachable — {error.message}</p>
        ) : (
          <p className="mono mt-1">
            connected · queue depth{" "}
            <span className="font-semibold">{data?.queue_depth ?? 0}</span>
          </p>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <Link href="/provider" className="mono text-[var(--accent)]">
          /provider — register an endpoint and watch its paid requests
        </Link>
        <Link href="/agent" className="mono text-[var(--accent)]">
          /agent — the delegation tree, draining live
        </Link>
        <Link href="/feed" className="mono text-[var(--accent)]">
          /feed — every settled charge, with latency and settlement panels
        </Link>
      </section>
    </div>
  );
}
