-- Co-op sessions' daily totals by the transport they ran over, from the summary each page reports as its session
-- ends (docs/rewrite/network-coop.md, "Telemetry"): no room, seat, token, round trip or row of its own per session.
-- `metric` names a counter and `bucket` its histogram bucket: sessions, seconds, desyncs and stalled frames have one
-- (0); rtt counts sessions by their round trip's bucket, depth rollbacks by how many ticks they took back (bucket 0
-- is one tick) and frame frames by the time their ticks took (crimson-core/client/web/analytics.json, "coop").
CREATE TABLE coop_totals (
  day TEXT NOT NULL,
  transport TEXT NOT NULL,
  metric TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, transport, metric, bucket)
) WITHOUT ROWID;
