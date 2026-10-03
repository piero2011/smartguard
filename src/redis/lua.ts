/**
 * Script Lua de decisión: UNA sola ida y vuelta a Redis por petición puntuada (puntos 74 y 75).
 *
 * Qué hace, de forma atómica:
 *  1. Lee score de IP y de huella con decay lineal aplicado (sin escribir si no hay señales).
 *  2. Si hay señales: suma deltas, cuenta "hits" en una ventana corta y añade bonus de
 *     escaneo rápido cuando se alcanza el umbral (una vez por ventana).
 *  3. Guarda el motivo (explicabilidad) en una lista acotada.
 *  4. Devuelve el TTL de los bans de IP y huella.
 *
 * El tráfico normal (sin señales) NO crea claves: solo lecturas. Así un NAT con miles de
 * peticiones legítimas no consume memoria en Redis.
 *
 * KEYS[1] hash reputación IP        smartguard:ip:{ipKey}
 * KEYS[2] hash reputación huella    smartguard:fp:{fpKey}
 * KEYS[3] ban IP                    smartguard:ban:{ipKey}      (o auditban: en AUDIT)
 * KEYS[4] ban huella                smartguard:ban:fp:{fpKey}   (o auditban:fp:)
 * KEYS[5] lista de motivos          smartguard:reasons:{ipKey}
 * KEYS[6] huellas vistas de la IP   smartguard:fps:{ipKey}      (para poder resetearlas al desbloquear)
 *
 * ARGV: now_ms, ipDelta, fpDelta, strongDelta, decayPerMinute, ipTtlSec, fpTtlSec,
 *       burstWindowMs, burstThreshold, burstBonus, reason, reasonsMax, isHit(0|1), country, fpKey
 *
 * Retorno: { ipBanPttl, fpBanPttl, ipScore*100, strong*100, fpScore*100, bonus, decay*100, windowHits }
 *
 * Campos del hash: s=score g=evidencia fuerte t=último cálculo wh/ws=ventana de hits
 *                  f=first seen l=last seen h=hits totales cc=país (CF-IPCountry)
 */
export const DECIDE_LUA = `
local now = tonumber(ARGV[1])
local ipDelta = tonumber(ARGV[2])
local fpDelta = tonumber(ARGV[3])
local strongDelta = tonumber(ARGV[4])
local decayPerMs = tonumber(ARGV[5]) / 60000
local ipTtl = tonumber(ARGV[6])
local fpTtl = tonumber(ARGV[7])
local win = tonumber(ARGV[8])
local thr = tonumber(ARGV[9])
local bonusPts = tonumber(ARGV[10])
local reason = ARGV[11]
local rmax = tonumber(ARGV[12])
local isHit = ARGV[13] == '1'
local cc = ARGV[14]
local fpId = ARGV[15]

local function cur(key)
  local v = redis.call('HMGET', key, 's', 't', 'g', 'wh', 'ws')
  local s = tonumber(v[1]) or 0
  local t = tonumber(v[2]) or now
  local g = tonumber(v[3]) or 0
  local dec = math.max(0, now - t) * decayPerMs
  return math.max(0, s - dec), math.max(0, g - dec), tonumber(v[4]) or 0, tonumber(v[5]) or 0, math.min(s, dec)
end

local ipS, ipG, wh, ws, ipDec = cur(KEYS[1])
local fpS = cur(KEYS[2])
local bonus = 0

if ipDelta > 0 or isHit then
  if isHit then
    if now - ws > win then ws = now; wh = 0 end
    wh = wh + 1
    if wh == thr then bonus = bonusPts end
  end
  ipS = ipS + ipDelta + bonus
  ipG = ipG + strongDelta + bonus
  redis.call('HSET', KEYS[1], 's', tostring(ipS), 't', tostring(now), 'g', tostring(ipG),
    'wh', tostring(wh), 'ws', tostring(ws), 'l', tostring(now))
  redis.call('HSETNX', KEYS[1], 'f', tostring(now))
  if isHit then redis.call('HINCRBY', KEYS[1], 'h', 1) end
  if cc ~= '' then redis.call('HSET', KEYS[1], 'cc', cc) end
  redis.call('EXPIRE', KEYS[1], ipTtl)
end

if fpDelta > 0 then
  fpS = fpS + fpDelta
  redis.call('HSET', KEYS[2], 's', tostring(fpS), 't', tostring(now))
  redis.call('EXPIRE', KEYS[2], fpTtl)
  if redis.call('SCARD', KEYS[6]) < 500 then redis.call('SADD', KEYS[6], fpId) end
  redis.call('EXPIRE', KEYS[6], fpTtl)
end

if reason ~= '' or bonus > 0 then
  local r = reason
  if bonus > 0 then
    if r ~= '' then r = r .. ',' end
    r = r .. 'rapid_scanning+' .. bonus
  end
  redis.call('LPUSH', KEYS[5], tostring(now) .. '|' .. r)
  redis.call('LTRIM', KEYS[5], 0, rmax - 1)
  redis.call('EXPIRE', KEYS[5], math.max(ipTtl, 86400))
end

return { redis.call('PTTL', KEYS[3]), redis.call('PTTL', KEYS[4]),
  math.floor(ipS * 100), math.floor(ipG * 100), math.floor(fpS * 100),
  bonus, math.floor(ipDec * 100), wh }
`;

/**
 * Throttle de ventana fija para IPs en RATE_LIMIT/RESTRICTION.
 * KEYS[1] contador · ARGV[1] ttl segundos · Retorno: contador actual.
 */
export const THROTTLE_LUA = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1])) end
return c
`;
