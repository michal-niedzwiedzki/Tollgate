-- architecture.md §5.2: every charge decrements every capability in the chain, not just the
-- leaf. Rebuilding a level's spend from Postgres (Task 5.6) therefore needs the whole chain
-- that was charged, not only the capability that made the request.
--
-- `capability_hash` (0001) keeps its meaning: the leaf, i.e. which agent spent. It stays the
-- indexed column for "what did this agent spend on". `chain_hashes` is the full root-first
-- list and carries no foreign key, deliberately — a payer-level charge with no capability
-- chain at all still records its one synthetic level here, so the boot rebuild has exactly
-- one code path rather than a special case per funding style.
ALTER TABLE authorisations ADD COLUMN chain_hashes BYTEA[];
