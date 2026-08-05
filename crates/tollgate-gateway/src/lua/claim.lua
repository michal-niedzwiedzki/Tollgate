-- The atomic claim. architecture.md §9.1 steps 1, 2, 3, 5, 6, 7.
--
-- Step 4 (window buckets) is deliberately absent: window budgets are out of scope
-- for the MVP per plan.md assumption A4. There is no tg:window:* key.
--
-- The key list is variadic in the number of capability levels so that Phase 5 can
-- present a full capability chain here without rewriting the script. Phase 3 calls
-- it with exactly one level, keyed by the payer.
--
-- KEYS[1]                  tg:nonce:{nonce}
-- KEYS[2 .. n+1]           tg:cap:{hash}:spent   one per level, root first
-- KEYS[n+2]                tg:reservations
-- KEYS[n+3 .. 2n+2]        tg:cap:{hash}:meta    one per level, root first
--
-- ARGV[1]                  amount, in token base units
-- ARGV[2]                  nonce TTL in seconds
-- ARGV[3]                  n, the level count
-- ARGV[4]                  nonce, hex
-- ARGV[5]                  payer address
-- ARGV[6]                  provider slug
-- ARGV[7 .. n+6]           capability hash per level, root first
--
-- Returns exactly one of:
--   {'replay'}
--   {'missing_meta', level, cap_hash}
--   {'cap_exceeded', level, cap_hash, max_per_request}
--   {'insufficient', level, cap_hash, remaining}
--   {'ok', stream_id}
--
-- `level` is 0-based and root-first, so level 0 is the funding root and the last
-- level is the leaf actually making the request.
--
-- Amounts are compared as Lua numbers, which are exact to 2^53. At USDC's 6
-- decimals that is ~9e9 USDC per counter, far above anything this gateway meters.

local amount = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local levels = tonumber(ARGV[3])

local nonce_key = KEYS[1]
local stream_key = KEYS[levels + 2]

-- 1. Replay. The nonce is the idempotency key end to end (architecture.md §9.4),
--    so this is the first thing checked and the cheapest way to fail.
if redis.call('EXISTS', nonce_key) == 1 then
    return { 'replay' }
end

-- Every read happens here, before any check and long before any write. Nothing
-- below the "first mutation" marker may fail in a way that leaves this script
-- half-applied.
local cap_hash = {}
local max_total = {}
local max_per_request = {}
local spent = {}

for i = 1, levels do
    cap_hash[i] = ARGV[6 + i]

    local meta = redis.call('HMGET', KEYS[levels + 2 + i], 'max_total', 'max_per_request')
    max_total[i] = tonumber(meta[1])
    max_per_request[i] = tonumber(meta[2])

    -- A level whose meta is absent or unparseable is an error, never a silent
    -- pass: an unmetered level would be an uncapped level.
    if not max_total[i] or not max_per_request[i] then
        return { 'missing_meta', i - 1, cap_hash[i] }
    end

    -- A level that has never been spent against has no counter yet.
    spent[i] = tonumber(redis.call('GET', KEYS[i + 1]) or '0')
end

-- 2. Per-request cap, checked across every level before any total is considered,
--    so an oversized request is reported as cap_exceeded rather than as a
--    coincidental insufficient at some other level.
for i = 1, levels do
    if amount > max_per_request[i] then
        return { 'cap_exceeded', i - 1, cap_hash[i], max_per_request[i] }
    end
end

-- 3. Total cap, every level. This is the check the v1 design raced on.
for i = 1, levels do
    if spent[i] + amount > max_total[i] then
        return { 'insufficient', i - 1, cap_hash[i], max_total[i] - spent[i] }
    end
end

-- ---- first mutation ----------------------------------------------------------
-- Everything from here is unconditional. All checks passed, all reads are done.

-- 5. Claim the nonce. The caller sets the TTL from validBefore - now + skew and
--    never from a constant, so the Redis guard always outlives the signature
--    (architecture.md §9.2).
redis.call('SET', nonce_key, 1, 'EX', ttl)

-- 6. Charge every level, not just the leaf. This is what makes a supervisor's
--    budget visibly drain as its workers spend (architecture.md §5.2).
for i = 1, levels do
    redis.call('INCRBY', KEYS[i + 1], amount)
end

-- 7. The reservation enters the stream in the same atomic execution as the
--    decrement, so balance and reservation live or die together and a crash
--    before the Postgres write cannot lose the spend (architecture.md §9.3).
local stream_id = redis.call('XADD', stream_key, '*',
    'nonce', ARGV[4],
    'payer', ARGV[5],
    'provider', ARGV[6],
    'amount', ARGV[1],
    'cap_hashes', table.concat(cap_hash, ','))

return { 'ok', stream_id }
