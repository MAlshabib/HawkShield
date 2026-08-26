import type { NextConfig } from "next"

/**
 * HawkShield frontend.
 *
 * `next build` produces a fully static export in `frontend/out/`, which the
 * FastAPI service on the Pi mounts at `/` (see docs/CONTRACT.md §1). Because the
 * API and the UI are then same-origin, no rewrites/proxy are needed.
 *
 * `next dev` still works for laptop development against a remote Pi: set
 * `NEXT_PUBLIC_API_BASE=http://<pi-ip>:8000` in `frontend/.env.local`.
 */
const nextConfig: NextConfig = {
  // Static HTML export -> frontend/out
  output: "export",

  // No Next.js image optimisation server exists in a static export.
  images: { unoptimized: true },

  // Emit `out/home/index.html` etc. so a plain static file server (and FastAPI's
  // StaticFiles with html=True) resolves /home without an extension.
  trailingSlash: true,
}

export default nextConfig
