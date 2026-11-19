"""Record assets/demo.gif from a real run of Roro.

    python3 scripts/demo-gif/make.py

It builds roro, a stand-in "notes" MCP server, and a small agent into a temp
folder, runs `roro protect` against a made-up Cursor config in a throwaway
home folder, makes real tool calls through Roro, and draws the captured
output as a terminal. Nothing in your own home folder is touched. Every line
of output in the GIF is what the commands printed; only the typing is drawn.

Needs Go, Google Chrome (macOS path below), and ImageMagick (`magick`).
"""
import html, json, os, shutil, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
S = tempfile.mkdtemp(prefix="roro-demo-")
home, bins, frames = f"{S}/home", f"{S}/bin", f"{S}/frames"
os.makedirs(bins)
for name, pkg in (("roro", "./cmd/roro"), ("notes-server", "./scripts/demo-gif/notes"), ("agent", "./scripts/demo-gif/agent")):
    subprocess.run(["go", "build", "-o", f"{bins}/{name}", pkg], cwd=ROOT, check=True)
for d in (home, frames):
    shutil.rmtree(d, ignore_errors=True)
os.makedirs(f"{home}/.cursor"); os.makedirs(frames)
json.dump({"mcpServers": {"notes": {"command": f"{bins}/notes-server", "args": []},
                          "docs": {"url": "https://example.com/mcp"}}},
          open(f"{home}/.cursor/mcp.json", "w"), indent=2)
env = dict(os.environ, HOME=home)

def run(*a):
    r = subprocess.run(a, env=env, capture_output=True, text=True)
    return (r.stdout + r.stderr).replace(home, "~").replace(bins + "/", "").rstrip("\n").split("\n")

roro, agent = f"{bins}/roro", f"{bins}/agent"
protect = run(roro, "protect", "--yes")
run(agent, json.dumps([
    {"tool": "search", "args": {"query": "launch plan"}},
    {"tool": "save", "args": {"text": "key AKIAIOSFODNN7EXAMPLE"}},
    {"tool": "search", "args": {"query": "meeting"}}]))
logs1 = run(roro, "logs", "--kind", "tool_call")
kill = run(roro, "kill")
run(agent, json.dumps([{"tool": "search", "args": {"query": "budget"}}]))
logs2 = run(roro, "logs", "--decision", "deny")

def cls(line):
    if " deny " in line or line.startswith("killed"): return "r"
    if " allow " in line or "will be protected" in line: return "g"
    if "skipped:" in line or line.startswith("SEQ"): return "d"
    return "t"

timeline = []  # (lines, seconds)
screen = []
def show(sec): timeline.append((list(screen), sec))
def typed(cmd, comment=False):
    k = "c" if comment else "p"
    pre = "" if comment else "$ "
    step = 6 if comment else 3
    screen.append((k, pre))
    for i in range(step, len(cmd) + step, step):
        screen[-1] = (k, pre + cmd[:i] + ("" if i >= len(cmd) else "█"))
        show(0.09)
    show(0.45)
def out(lines, hold):
    for l in lines: screen.append((cls(l), l))
    show(hold)

screen.append(("p", "$ ")); show(0.8); screen.pop()
typed("roro protect --yes"); out(protect, 4.2)
screen.clear()
typed("# Keep using Cursor as usual. Later, see what it did:", True)
typed("roro logs --kind tool_call"); out(logs1, 5.0)
screen.append(("t", ""))
typed("# Something looks wrong? Stop every agent:", True)
typed("roro kill"); out(kill, 1.8)
typed("roro logs --decision deny"); out(logs2, 5.5)

W, H, PER = 960, 440, 18
CSS = f"""body{{margin:0;background:#0d1117}}
.w{{width:{W}px;height:{H}px;box-sizing:border-box;padding:46px 22px 0;position:relative;overflow:hidden;
font:13px/21px ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre;color:#c9d1d9}}
.dots{{position:absolute;top:16px;left:18px}}.dots i{{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:8px}}
.p{{color:#fff;font-weight:600}}.g{{color:#7ee787}}.r{{color:#ff7b72}}.d{{color:#8b949e}}.c{{color:#79c0ff}}"""
def block(lines):
    body = "\n".join(f'<span class="{k}">{html.escape(t)}</span>' for k, t in lines)
    return ('<div class="w"><div class="dots"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i>'
            f'<i style="background:#28c840"></i></div>{body}</div>')
args = []
for start in range(0, len(timeline), PER):
    chunk = timeline[start:start + PER]
    page, png = f"{frames}/s{start}.html", f"{frames}/s{start}.png"
    open(page, "w").write(f'<meta charset="utf-8"><style>{CSS}</style>' + "".join(block(l) for l, _ in chunk))
    subprocess.run(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--headless=new", "--disable-gpu",
                    "--hide-scrollbars", f"--screenshot={png}", f"--window-size={W},{H * len(chunk)}", f"file://{page}"],
                   capture_output=True)
    for j, (_, sec) in enumerate(chunk):
        f = f"{frames}/{start + j:03d}.png"
        subprocess.run(["magick", png, "-crop", f"{W}x{H}+0+{j * H}", "+repage", f], check=True)
        args += ["-delay", str(round(sec * 100)), f]
subprocess.run(["magick", *args, "-colors", "32", "-layers", "Optimize", "-loop", "0", f"{ROOT}/assets/demo.gif"], check=True)
shutil.rmtree(S, ignore_errors=True)
print(len(timeline), "frames,", round(sum(s for _, s in timeline), 1), "s")
