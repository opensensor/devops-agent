-- Add per-incident metrics captured at detection time.
-- failure_count: number of 401/403 requests from the IP within the window.
-- details:       JSON blob (status breakdown, methods, top paths, targeted
--                hosts, window, last-seen) used to explain the incident in the UI.

ALTER TABLE incidents ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN details TEXT;
