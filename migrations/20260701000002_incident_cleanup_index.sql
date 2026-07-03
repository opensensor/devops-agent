-- Add index on detected_at for incident retention/cleanup queries.
-- Enables efficient DELETE of resolved incidents older than a threshold.

CREATE INDEX IF NOT EXISTS idx_incidents_detected_at ON incidents(detected_at);
