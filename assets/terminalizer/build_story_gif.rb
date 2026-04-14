#!/usr/bin/env ruby

require 'cgi'
require 'fileutils'

WIDTH = 920
HEIGHT = 458
INNER_X = 20
INNER_Y = 20
INNER_W = 880
INNER_H = 418
LINE_HEIGHT = 32
TEXT_X = 36
TEXT_Y = 36
FONT_SIZE = 18
FONT_PATH = '/System/Library/Fonts/Supplemental/Andale Mono.ttf'

def render_frame(text, highlights, output_path)
  lines = text.split("\n", -1)
  command = [
    'magick',
    '-size', "#{WIDTH}x#{HEIGHT}",
    'xc:#1b1b1b',
    '-fill', '#0b1020',
    '-draw', "rectangle #{INNER_X},#{INNER_Y} #{INNER_X + INNER_W},#{INNER_Y + INNER_H}",
    '-font', FONT_PATH,
    '-pointsize', FONT_SIZE.to_s
  ]

  lines.each_with_index do |line, index|
    y = TEXT_Y + index * LINE_HEIGHT
    color = highlights.fetch(index, line.start_with?('#') ? '#f6d7a7' : '#e5e7eb')
    escaped = line.gsub('\\', '\\\\').gsub("'", %q(\'))
    command << '-fill' << color
    command << '-draw' << "text #{TEXT_X},#{y} '#{escaped}'"
  end

  command << output_path
  system(*command, exception: true)
end

frames = [
  ['# foxguard dark demo', { 0 => '#f6d7a7' }, 90],
  ["# foxguard dark demo\n# code scan, secrets, baseline", { 0 => '#f6d7a7', 1 => '#f6d7a7' }, 90],
  ["# foxguard dark demo\n# code scan, secrets, baseline\n\n$ ls -1 stor", { 0 => '#f6d7a7', 1 => '#f6d7a7' }, 80],
  ["# foxguard dark demo\n# code scan, secrets, baseline\n\n$ ls -1 story-target\nroutes.js\nsecrets.env\nservices.js",
   { 0 => '#f6d7a7', 1 => '#f6d7a7' }, 120],
  ["# explain traces source -> sink\n$ fg story-target --expl", { 0 => '#f6d7a7' }, 80],
  [
    "# explain traces source -> sink\n$ fg story-target --explain || true\n\nstory-target/routes.js · 4 issues\n\nHIGH  Hardcoded session secret\njs/express-no-hardcoded-session-secret (CWE-798)  line 7:25\nconst sessionConfig = { secret: \"keyboard-cat-secret\" };", {
      0 => '#f6d7a7', 4 => '#f87171', 5 => '#22d3ee'
    }, 110
  ],
  [
    "# explain traces source -> sink\n$ fg story-target --explain || true\n\nstory-target/routes.js · 4 issues\n\nCRITICAL  req.query reaches SQL .query() call\njs/taint-sql-injection (CWE-89)  line 12:16\nsource -> story-target/routes.js:11  req.query\nsink   -> story-target/routes.js:12  SQL .query() call\nFix: Use parameterized queries\n\nCRITICAL  req.query reaches child_process.exec()\njs/taint-command-injection (CWE-78)  line 18:3\nsource -> story-target/routes.js:17  req.query\nsink   -> story-target/routes.js:18  child_process.exec()\nFix: Pass args to child_process.execFile()\n\n5 issues  2 files · 0.01s", {
      0 => '#f6d7a7', 4 => '#c4b5fd', 5 => '#22d3ee', 6 => '#fbbf24', 7 => '#f87171', 8 => '#6ee7b7', 10 => '#c4b5fd', 11 => '#22d3ee', 12 => '#fbbf24', 13 => '#f87171', 14 => '#6ee7b7'
    }, 140
  ],
  ["# secrets are redacted\n$ fg secrets story-t", { 0 => '#f6d7a7' }, 80],
  [
    "# secrets are redacted\n$ fg secrets story-target || true\n\nstory-target/secrets.env · 4 issues\n\nCRITICAL  Possible AWS access key ID detected\nAWS_ACCESS_KEY_ID=[REDACTED]\n\nCRITICAL  Possible GitHub personal access token detected\nGITHUB_TOKEN=[REDACTED]\n\nCRITICAL  Possible Stripe live secret key detected\nSTRIPE_SECRET_KEY=[REDACTED]\n\n4 issues  3 files · 0.01s", {
      0 => '#f6d7a7', 4 => '#c4b5fd', 7 => '#c4b5fd', 10 => '#c4b5fd'
    }, 130
  ],
  ["# baseline existing findings\n$ fg baseline story-target --output .demo-baseli", { 0 => '#f6d7a7' }, 80],
  [
    "# baseline existing findings\n$ fg baseline story-target --output .demo-baseline.json\nWrote baseline with 5 finding(s) to .demo-baseline.json", { 0 => '#f6d7a7' }, 110
  ],
  ["# next run stays clean\n$ fg story-target --baseline .demo-baseline.json\n\n✔ Scanned 2 files in 0.01s.",
   { 0 => '#f6d7a7', 3 => '#6ee7b7' }, 150]
]

out_dir = File.join(__dir__, '.story_frames')
FileUtils.rm_rf(out_dir)
FileUtils.mkdir_p(out_dir)

delay_args = []

frames.each_with_index do |(text, highlights, delay), index|
  png_path = File.join(out_dir, format('frame-%03d.png', index))
  render_frame(text, highlights, png_path)
  delay_args << ['-delay', delay.to_s, png_path]
end

gif_path = File.expand_path('../foxguard-terminalizer-story.gif', __dir__)
system('magick', *delay_args.flatten, '-loop', '0', gif_path, exception: true)
