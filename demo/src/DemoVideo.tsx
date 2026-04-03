import {
  AbsoluteFill,
  interpolate,
  useCurrentFrame,
  useVideoConfig,
  Sequence,
  spring,
} from "remotion";
import { loadFont as loadBricolage } from "@remotion/google-fonts/BricolageGrotesque";
import { loadFont as loadJakarta } from "@remotion/google-fonts/PlusJakartaSans";
import { loadFont as loadMartian } from "@remotion/google-fonts/MartianMono";

const { fontFamily: bricolage } = loadBricolage("normal", {
  weights: ["400", "600", "700"],
  subsets: ["latin"],
});

const { fontFamily: jakarta } = loadJakarta("normal", {
  weights: ["400", "500", "600"],
  subsets: ["latin"],
});

const { fontFamily: martian } = loadMartian("normal", {
  weights: ["400", "500"],
  subsets: ["latin"],
});

// ── Colors (foxguard noir palette) ──
const C = {
  bg: "#0C0A09",
  surface: "#1C1917",
  border: "#292524",
  fox: "#d97706",
  foxLight: "#f59e0b",
  foxGlow: "rgba(245, 158, 11, 0.25)",
  white: "#FAFAF9",
  text: "#D6D3D1",
  dimmed: "#78716C",
  muted: "#57534E",
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  blue: "#3b82f6",
  green: "#22c55e",
  // Language colors
  js: "#F7DF1E",
  py: "#3776AB",
  rb: "#CC342D",
  java: "#ED8B00",
  go: "#00ADD8",
};

// ── Scene boundaries (seconds) ──
const S = {
  introEnd: 3,
  cmdStart: 3,
  cmdEnd: 6,
  findingsStart: 6,
  findingsEnd: 14,
  speedStart: 14,
  speedEnd: 18,
  ctaStart: 18,
  ctaEnd: 20,
};

// ── Findings data ──
const FINDINGS = [
  { file: "src/auth/login.js", line: "14:5", severity: "critical", color: C.js, rule: "js/no-sql-injection", cwe: "CWE-89", desc: "SQL query built with template literal interpolation" },
  { file: "app/views.py", line: "42:1", severity: "high", color: C.py, rule: "py/no-hardcoded-secret", cwe: "CWE-798", desc: "Hardcoded secret in 'api_key'" },
  { file: "app/controllers/users.rb", line: "23:5", severity: "critical", color: C.rb, rule: "rb/no-sql-injection", cwe: "CWE-89", desc: "String interpolation in ActiveRecord query" },
  { file: "UserService.java", line: "67:12", severity: "high", color: C.java, rule: "java/no-xxe", cwe: "CWE-611", desc: "XML parser without entity protection" },
  { file: "cmd/server.go", line: "31:3", severity: "high", color: C.go, rule: "go/no-ssrf", cwe: "CWE-918", desc: "http.Get with variable URL" },
];

// ── Main Component ──
export const DemoVideo = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: C.bg,
        fontFamily: jakarta,
        color: C.white,
        overflow: "hidden",
      }}
    >
      {/* Subtle grid */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          opacity: 0.03,
          backgroundImage: `
            linear-gradient(rgba(245,158,11,0.2) 1px, transparent 1px),
            linear-gradient(90deg, rgba(245,158,11,0.2) 1px, transparent 1px)
          `,
          backgroundSize: "60px 60px",
        }}
      />

      {/* Vignette */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: "radial-gradient(ellipse at center, transparent 30%, rgba(0,0,0,0.7) 100%)",
          pointerEvents: "none",
        }}
      />

      {/* Scene 1: Intro */}
      <Sequence from={0} durationInFrames={Math.floor(S.introEnd * fps)} layout="none">
        <IntroScene />
      </Sequence>

      {/* Scene 2: Command */}
      <Sequence from={Math.floor(S.cmdStart * fps)} durationInFrames={Math.floor((S.cmdEnd - S.cmdStart) * fps)} layout="none">
        <CommandScene />
      </Sequence>

      {/* Scene 3: Findings */}
      <Sequence from={Math.floor(S.findingsStart * fps)} durationInFrames={Math.floor((S.findingsEnd - S.findingsStart) * fps)} layout="none">
        <FindingsScene />
      </Sequence>

      {/* Scene 4: Speed */}
      <Sequence from={Math.floor(S.speedStart * fps)} durationInFrames={Math.floor((S.speedEnd - S.speedStart) * fps)} layout="none">
        <SpeedScene />
      </Sequence>

      {/* Scene 5: CTA */}
      <Sequence from={Math.floor(S.ctaStart * fps)} durationInFrames={Math.floor((S.ctaEnd - S.ctaStart) * fps)} layout="none">
        <CTAScene />
      </Sequence>

      {/* Progress bar */}
      <div
        style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          height: 3,
          backgroundColor: "rgba(245, 158, 11, 0.1)",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${(sec / S.ctaEnd) * 100}%`,
            backgroundColor: C.fox,
            boxShadow: `0 0 8px ${C.foxGlow}`,
            borderRadius: "0 2px 2px 0",
          }}
        />
      </div>
    </AbsoluteFill>
  );
};

// ── Scene 1: INTRO ──
const IntroScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  const logoScale = spring({
    frame,
    fps,
    config: { damping: 12, stiffness: 80, mass: 0.8 },
    durationInFrames: 40,
  });

  const logoOpacity = interpolate(frame, [0, 12], [0, 1], {
    extrapolateRight: "clamp",
  });

  const titleOpacity = interpolate(sec, [0.5, 1.0], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const subtitleOpacity = interpolate(sec, [1.0, 1.5], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const exitOpacity = interpolate(sec, [2.4, 3.0], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
        opacity: exitOpacity,
      }}
    >
      {/* Fox logo */}
      <svg
        width={80}
        height={80}
        viewBox="0 0 64 64"
        fill="none"
        style={{
          opacity: logoOpacity,
          transform: `scale(${logoScale})`,
          marginBottom: 24,
        }}
      >
        <path d="M8 8L20 28L32 20L44 28L56 8L52 32L44 44L36 52H28L20 44L12 32L8 8Z" fill="#F59E0B" fillOpacity="0.15" stroke="#F59E0B" strokeWidth="2" strokeLinejoin="round"/>
        <circle cx="24" cy="32" r="2.5" fill="#F59E0B"/>
        <circle cx="40" cy="32" r="2.5" fill="#F59E0B"/>
      </svg>

      {/* Title */}
      <div
        style={{
          fontFamily: bricolage,
          fontSize: 72,
          fontWeight: 700,
          letterSpacing: "-0.03em",
          opacity: titleOpacity,
        }}
      >
        fox<span style={{ color: C.foxLight }}>guard</span>
      </div>

      {/* Subtitle */}
      <div
        style={{
          fontFamily: jakarta,
          fontSize: 22,
          color: C.dimmed,
          marginTop: 16,
          opacity: subtitleOpacity,
        }}
      >
        A security scanner as fast as a linter.
      </div>
    </AbsoluteFill>
  );
};

// ── Scene 2: COMMAND ──
const CommandScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  const enterOpacity = interpolate(sec, [0, 0.3], [0, 1], {
    extrapolateRight: "clamp",
  });

  const cmdText = "$ foxguard .";
  const charsVisible = Math.min(
    Math.floor(interpolate(sec, [0.3, 1.5], [0, cmdText.length], {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
    })),
    cmdText.length
  );

  const scanningOpacity = interpolate(sec, [1.8, 2.2], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
        opacity: enterOpacity,
      }}
    >
      <div
        style={{
          width: 800,
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 12,
          overflow: "hidden",
        }}
      >
        {/* Title bar */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 16px",
            borderBottom: `1px solid ${C.border}`,
            background: C.bg,
          }}
        >
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ef4444", opacity: 0.8 }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#eab308", opacity: 0.8 }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#22c55e", opacity: 0.8 }} />
          <div style={{ fontFamily: martian, fontSize: 10, color: C.muted, margin: "0 auto", letterSpacing: "0.1em" }}>terminal</div>
        </div>

        {/* Content */}
        <div style={{ padding: "24px 28px", fontFamily: martian, fontSize: 15, lineHeight: 2.2 }}>
          <div>
            <span style={{ color: C.foxLight }}>{cmdText.slice(0, 1)}</span>
            <span style={{ color: C.white }}>{cmdText.slice(1, charsVisible)}</span>
            {charsVisible < cmdText.length && (
              <span
                style={{
                  display: "inline-block",
                  width: 8,
                  height: 18,
                  background: C.foxLight,
                  verticalAlign: "text-bottom",
                  opacity: Math.sin(frame * 0.3) > 0 ? 1 : 0,
                }}
              />
            )}
          </div>
          <div style={{ color: C.muted, opacity: scanningOpacity }}>
            Scanning 2,814 files...
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};

// ── Scene 3: FINDINGS ──
const FindingsScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <div
        style={{
          width: 800,
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 12,
          overflow: "hidden",
        }}
      >
        {/* Title bar */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 16px",
            borderBottom: `1px solid ${C.border}`,
            background: C.bg,
          }}
        >
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ef4444", opacity: 0.8 }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#eab308", opacity: 0.8 }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#22c55e", opacity: 0.8 }} />
          <div style={{ fontFamily: martian, fontSize: 10, color: C.muted, margin: "0 auto", letterSpacing: "0.1em" }}>terminal</div>
        </div>

        <div style={{ padding: "20px 28px", fontFamily: martian, fontSize: 13, lineHeight: 1.9 }}>
          <div><span style={{ color: C.foxLight }}>$</span> <span style={{ color: C.white }}>foxguard .</span></div>
          <div style={{ color: C.muted, marginBottom: 8 }}>Scanning 2,814 files...</div>

          {FINDINGS.map((f, i) => {
            const findingDelay = i * 1.2;
            const findingOpacity = interpolate(sec, [findingDelay, findingDelay + 0.4], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            });
            const slideY = interpolate(sec, [findingDelay, findingDelay + 0.4], [10, 0], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            });

            const sevColor = f.severity === "critical" ? C.critical : C.high;

            return (
              <div
                key={i}
                style={{
                  opacity: findingOpacity,
                  transform: `translateY(${slideY}px)`,
                  marginBottom: 6,
                }}
              >
                <div>
                  <span style={{ color: f.color, opacity: 0.8 }}>{f.file}</span>
                  <span style={{ color: C.muted }}>:{f.line}</span>
                </div>
                <div style={{ paddingLeft: 20 }}>
                  <span style={{ color: sevColor, fontWeight: 600, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    {f.severity}
                  </span>
                  <span style={{ color: C.text, marginLeft: 8 }}>{f.rule}</span>
                  <span style={{ color: C.muted, marginLeft: 8 }}>{f.cwe}</span>
                </div>
              </div>
            );
          })}

          {/* Summary line */}
          {(() => {
            const summaryOpacity = interpolate(sec, [6.5, 7.0], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            });
            return (
              <div
                style={{
                  opacity: summaryOpacity,
                  borderTop: `1px solid ${C.border}`,
                  paddingTop: 10,
                  marginTop: 10,
                }}
              >
                Found <span style={{ color: C.foxLight, fontWeight: 600 }}>5 issues</span> in{" "}
                <span style={{ color: C.foxLight, fontWeight: 600 }}>2,814 files</span>{" "}
                <span style={{ color: C.muted }}>(0.92s)</span>
              </div>
            );
          })()}
        </div>
      </div>
    </AbsoluteFill>
  );
};

// ── Scene 4: SPEED ──
const SpeedScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  const enterOpacity = interpolate(sec, [0, 0.4], [0, 1], {
    extrapolateRight: "clamp",
  });

  const foxWidth = interpolate(sec, [0.4, 1.2], [0, 4], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const semgrepWidth = interpolate(sec, [0.8, 2.5], [0, 100], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const multiplierOpacity = interpolate(sec, [2.5, 3.0], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const multiplierScale = spring({
    frame: Math.max(0, frame - Math.floor(2.5 * fps)),
    fps,
    config: { damping: 8, stiffness: 100, mass: 0.6 },
    durationInFrames: 30,
  });

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
        opacity: enterOpacity,
      }}
    >
      <div style={{ width: 700, textAlign: "center" }}>
        <div
          style={{
            fontFamily: bricolage,
            fontSize: 36,
            fontWeight: 700,
            marginBottom: 8,
            letterSpacing: "-0.02em",
          }}
        >
          Linter speed, scanner depth
        </div>
        <div style={{ fontFamily: jakarta, fontSize: 16, color: C.dimmed, marginBottom: 48 }}>
          Scanning express repo (141 files)
        </div>

        {/* foxguard bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 16 }}>
          <div style={{ fontFamily: martian, fontSize: 12, color: C.dimmed, width: 90, textAlign: "right" }}>foxguard</div>
          <div style={{ flex: 1, height: 36, background: C.bg, borderRadius: 6, border: `1px solid ${C.border}`, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${foxWidth}%`,
                background: C.fox,
                borderRadius: 5,
                display: "flex",
                alignItems: "center",
                justifyContent: "flex-end",
                paddingRight: 10,
                fontFamily: martian,
                fontSize: 12,
                fontWeight: 600,
                color: C.bg,
                minWidth: 70,
              }}
            >
              0.284s
            </div>
          </div>
        </div>

        {/* Semgrep bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 40 }}>
          <div style={{ fontFamily: martian, fontSize: 12, color: C.muted, width: 90, textAlign: "right" }}>Semgrep</div>
          <div style={{ flex: 1, height: 36, background: C.bg, borderRadius: 6, border: `1px solid ${C.border}`, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${semgrepWidth}%`,
                background: C.muted,
                borderRadius: 5,
                display: "flex",
                alignItems: "center",
                justifyContent: "flex-end",
                paddingRight: 10,
                fontFamily: martian,
                fontSize: 12,
                fontWeight: 600,
                color: C.text,
                minWidth: 70,
              }}
            >
              17.4s
            </div>
          </div>
        </div>

        {/* Multiplier */}
        <div
          style={{
            opacity: multiplierOpacity,
            transform: `scale(${multiplierScale})`,
          }}
        >
          <span
            style={{
              fontFamily: bricolage,
              fontSize: 64,
              fontWeight: 700,
              color: C.foxLight,
              textShadow: `0 0 40px ${C.foxGlow}`,
            }}
          >
            61x
          </span>
          <span
            style={{
              fontFamily: jakarta,
              fontSize: 22,
              color: C.dimmed,
              marginLeft: 12,
            }}
          >
            faster
          </span>
        </div>
      </div>
    </AbsoluteFill>
  );
};

// ── Scene 5: CTA ──
const CTAScene = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sec = frame / fps;

  const enterOpacity = interpolate(sec, [0, 0.4], [0, 1], {
    extrapolateRight: "clamp",
  });

  const cmdScale = spring({
    frame,
    fps,
    config: { damping: 12, stiffness: 80 },
    durationInFrames: 30,
  });

  const statsOpacity = interpolate(sec, [0.5, 0.9], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const urlOpacity = interpolate(sec, [0.8, 1.2], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        justifyContent: "center",
        alignItems: "center",
        opacity: enterOpacity,
      }}
    >
      <div style={{ textAlign: "center" }}>
        {/* Command */}
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 12,
            padding: "16px 32px",
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 10,
            fontFamily: martian,
            fontSize: 20,
            marginBottom: 32,
            transform: `scale(${cmdScale})`,
          }}
        >
          <span style={{ color: C.muted }}>$</span>
          <span style={{ color: C.foxLight }}>npx foxguard .</span>
        </div>

        {/* Stats */}
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            gap: 40,
            fontFamily: martian,
            fontSize: 13,
            marginBottom: 32,
            opacity: statsOpacity,
          }}
        >
          <div>
            <span style={{ color: C.white, fontSize: 22, fontFamily: bricolage, fontWeight: 700 }}>118</span>
            <span style={{ color: C.muted, marginLeft: 6 }}>rules</span>
          </div>
          <div>
            <span style={{ color: C.white, fontSize: 22, fontFamily: bricolage, fontWeight: 700 }}>9</span>
            <span style={{ color: C.muted, marginLeft: 6 }}>languages</span>
          </div>
          <div>
            <span style={{ color: C.white, fontSize: 22, fontFamily: bricolage, fontWeight: 700 }}>&lt;1s</span>
            <span style={{ color: C.muted, marginLeft: 6 }}>scans</span>
          </div>
        </div>

        {/* URL */}
        <div
          style={{
            fontFamily: jakarta,
            fontSize: 18,
            color: C.dimmed,
            opacity: urlOpacity,
          }}
        >
          foxguard.dev
        </div>
      </div>
    </AbsoluteFill>
  );
};
