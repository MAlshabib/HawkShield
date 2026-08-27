"use client"

/**
 * DEPRECATED — superseded by `components/brand/logo.tsx`.
 *
 * The neon `drop-shadow` stack below overwrites the two colours the mark is
 * actually drawn in with a cyan the logo does not contain; `brand-spec.md`
 * rules it out. This file is left in place only because `components/navbar.tsx`
 * and `app/(app)/home/page.tsx` still import it. Delete it once both switch to
 * `<Logo />` / `<Wordmark />` from `@/components/brand/logo`.
 */

type Props = { 
  size?: number
  className?: string
  "aria-hidden"?: boolean 
}

export default function Logo({ size = 60, className = "", ...rest }: Props) {
  return (
    <div
      className={`logo ${className}`}
      style={{ width: size, height: size }}
      {...rest}
    >
      <style jsx>{`
        .logo {
          position: relative;
          background: url('/logo-neon.png') center/contain no-repeat;
          overflow: hidden;
          filter:
            drop-shadow(0 0 4px #00e5ff)
            drop-shadow(0 0 12px #00e5ff)
            drop-shadow(0 0 24px #00bfff);
        }

        .logo::after {
          content: '';
          position: absolute;
          inset: 0;
          pointer-events: none;
          -webkit-mask: url('/logo-neon.png') center/contain no-repeat;
                  mask: url('/logo-neon.png') center/contain no-repeat;
          background: linear-gradient(
            to top,
            rgba(255,255,255,0) 0%,
            rgba(144, 144, 144, 1) 12%,
            rgba(255,255,255,0) 24%
          );
          background-repeat: no-repeat;
          background-size: 100% 400%;
          background-position: 50% 120%;
          mix-blend-mode: screen;
          opacity: 0.9;
          animation: sweepPos 2.8s linear infinite;
        }

        @keyframes sweepPos {
          0%   { background-position: 50% -20%; }
          100% { background-position: 50% 120%; }
        }

        @media (prefers-reduced-motion: reduce) {
          .logo::after {
            animation: none;
          }
        }
      `}</style>
    </div>
  )
}
