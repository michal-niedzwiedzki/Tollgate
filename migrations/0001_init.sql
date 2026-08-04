CREATE TABLE providers (
  slug            TEXT PRIMARY KEY,
  upstream_url    TEXT NOT NULL,
  price_wei       NUMERIC NOT NULL,
  max_price_wei   NUMERIC,                    -- for the upto scheme
  scheme          TEXT NOT NULL DEFAULT 'exact',
  payout_address  BYTEA NOT NULL,
  timeout_ms      INT DEFAULT 30000,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE capabilities (
  hash            BYTEA PRIMARY KEY,          -- EIP-712 struct hash
  issuer          BYTEA NOT NULL,
  subject         BYTEA NOT NULL,
  parent_hash     BYTEA REFERENCES capabilities(hash),
  depth           INT NOT NULL,
  max_total_wei   NUMERIC NOT NULL,
  max_per_req_wei NUMERIC NOT NULL,
  allowlist       TEXT[],
  not_before      TIMESTAMPTZ NOT NULL,
  expiry          TIMESTAMPTZ NOT NULL,
  signature       BYTEA NOT NULL,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE authorisations (
  nonce           BYTEA PRIMARY KEY,          -- the EIP-3009 nonce
  payer           BYTEA NOT NULL,             -- signer of the payment payload
  capability_hash BYTEA REFERENCES capabilities(hash),
  provider_slug   TEXT REFERENCES providers(slug),
  amount_wei      NUMERIC NOT NULL,
  payload         JSONB NOT NULL,             -- full EIP-3009 payload
  signature       BYTEA NOT NULL,
  status          TEXT NOT NULL               -- reserved | voided | queued | settled | failed
                    CHECK (status IN ('reserved', 'voided', 'queued', 'settled', 'failed')),
  upstream_status INT,
  batch_id        BYTEA,
  tx_hash         BYTEA,
  receipt_sig     BYTEA,
  created_at      TIMESTAMPTZ DEFAULT now(),
  settled_at      TIMESTAMPTZ
);

CREATE INDEX ON authorisations (status) WHERE status = 'queued';
CREATE INDEX ON authorisations (payer, created_at DESC);
CREATE INDEX ON authorisations (capability_hash, created_at DESC);
