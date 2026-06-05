// data.js — the frontend's live data store.
//
// `MINOS_DATA` starts as the curated sample dataset (grounded in the real
// scanner taxonomy + the real ses-894ebdc2 Redis session) so the UI renders
// fully even with no backend. At startup `api.hydrate()` overlays live data
// from the FastAPI backend by mutating this same object in place — every
// module imports the same reference, so they all see the hydrated values.
//
// The JSON is shared verbatim with the backend
// (backend/src/mcp_security_analyzer/api/sample_data.json).

import sample from "./sample_data.json";

export const MINOS_DATA = { ...sample };

// Back-compat for any code that still reaches for the global.
if (typeof window !== "undefined") {
  window.MINOS_DATA = MINOS_DATA;
}
