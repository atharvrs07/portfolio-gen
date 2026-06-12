// ===== TERMINAL ENGINE =====

let terminalReady = false;
let cmdHistory = [];
let historyIndex = -1;
let currentInput = '';
let cursorPos = 0;
let inputLocked = false;

const PROMPT = 'bunny@atharv:~$ ';

const COMMANDS = {
  help: cmdHelp,
  whoami: cmdWhoami,
  skills: cmdSkills,
  projects: cmdProjects,
  github: cmdGithub,
  stack: cmdStack,
  xevonet: cmdXevonet,
  liquilink: cmdLiquilink,
  contact: cmdContact,
  age: cmdAge,
  clear: cmdClear,
  'sudo hire me': cmdHireMe,
  ls: cmdLs,
  'cat thoughts/': cmdThoughts,
  easter_egg: cmdEasterEgg,
  neofetch: cmdNeofetch,
  pwd: cmdPwd,
  date: cmdDate,
  uptime: cmdUptime,
  man: cmdMan,
};

const COMMAND_NAMES = Object.keys(COMMANDS);

function initTerminal() {
  if (terminalReady) return;
  terminalReady = true;

  const input = document.getElementById('terminalInput');
  const terminal = document.getElementById('terminal');

  input.addEventListener('input', onInput);
  input.addEventListener('keydown', onKeyDown);
  terminal.addEventListener('click', focusTerminal);

  // Mobile: ensure virtual keyboard can open
  input.addEventListener('focus', () => {
    setTimeout(scrollToBottom, 300);
  });

  runBootSequence();
}

function focusTerminal() {
  document.getElementById('terminalInput').focus({ preventScroll: true });
}

// ===== BOOT SEQUENCE =====

async function runBootSequence() {
  inputLocked = true;
  setInputVisible(false);

  const bootLines = [
    { text: '                                                        ', delay: 0 },
    { text: '   █████╗ ████████╗██╗  ██╗ █████╗ ██████╗ ██╗   ██╗  ', delay: 60, cls: 'bright' },
    { text: '  ██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔══██╗██║   ██║  ', delay: 60, cls: 'bright' },
    { text: '  ███████║   ██║   ███████║███████║██████╔╝██║   ██║  ', delay: 60, cls: 'bright' },
    { text: '  ██╔══██║   ██║   ██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝  ', delay: 60, cls: 'bright' },
    { text: '  ██║  ██║   ██║   ██║  ██║██║  ██║██║  ██║ ╚████╔╝   ', delay: 60, cls: 'bright' },
    { text: '  ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝    ', delay: 80, cls: 'bright' },
    { text: '                                                        ', delay: 0 },
    { text: '  Atharv OS v1.0  ·  Personal Terminal  ·  2025', delay: 120, cls: 'dim' },
    { text: '', delay: 60, cls: 'blank' },
    { text: '─────────────────────────────────────────────────────', delay: 80, cls: 'separator' },
    { text: '', delay: 60, cls: 'blank' },
    { text: 'Initializing Atharv OS v1.0...', delay: 150 },
    { text: '', delay: 60, cls: 'blank' },
    { text: 'Loading kernel modules...                    [  OK  ]', delay: 200, cls: 'dim' },
    { text: 'Mounting /projects...                        [  OK  ]', delay: 200, cls: 'dim' },
    { text: 'Mounting /skills...                          [  OK  ]', delay: 200, cls: 'dim' },
    { text: 'Mounting /thoughts...                        [  OK  ]', delay: 200, cls: 'dim' },
    { text: 'Starting identity daemon...                  [  OK  ]', delay: 200, cls: 'dim' },
    { text: 'Loading LiquiLink module...                  [  OK  ]', delay: 220, cls: 'dim' },
    { text: 'Loading XevoNet module...                    [  OK  ]', delay: 220, cls: 'dim' },
    { text: '', delay: 60, cls: 'blank' },
    { text: 'Loading modules: [■■■■■■■■■■] 100%', delay: 300, cls: 'accent' },
    { text: '', delay: 80, cls: 'blank' },
    { text: 'Boot complete. Welcome.', delay: 200, cls: 'bright' },
    { text: '', delay: 60, cls: 'blank' },
    { text: "Type 'help' to get started.", delay: 150, cls: 'dim' },
    { text: '', delay: 60, cls: 'blank' },
  ];

  let totalDelay = 0;
  for (const item of bootLines) {
    totalDelay += item.delay;
    await sleep(item.delay);
    printLine(item.text, item.cls || '');
    scrollToBottom();
  }

  inputLocked = false;
  setInputVisible(true);
  focusTerminal();
}

// ===== OUTPUT HELPERS =====

function printLine(text, cls = '') {
  const output = document.getElementById('terminalOutput');
  if (cls === 'blank') {
    const el = document.createElement('span');
    el.className = 'line blank';
    output.appendChild(el);
    return;
  }
  const lines = text.split('\n');
  for (const line of lines) {
    const el = document.createElement('span');
    el.className = 'line' + (cls ? ' ' + cls : '');
    el.textContent = line;
    output.appendChild(el);
  }
}

function printLines(lines, cls = '') {
  for (const line of lines) {
    if (typeof line === 'string') {
      printLine(line, cls);
    } else {
      printLine(line.text, line.cls || cls);
    }
  }
}

function printBlank() { printLine('', 'blank'); }

function scrollToBottom() {
  const wrapper = document.getElementById('terminalWrapper');
  if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
  // Also scroll the section
  const section = document.getElementById('techSection');
  if (section) section.scrollTop = section.scrollHeight;
}

function setInputVisible(v) {
  document.getElementById('inputRow').style.display = v ? 'flex' : 'none';
}

// ===== INPUT HANDLING =====

function onInput(e) {
  if (inputLocked) { e.target.value = ''; return; }
  currentInput = e.target.value;
  cursorPos = e.target.selectionStart;
  updateInputDisplay();
}

function onKeyDown(e) {
  if (inputLocked) return;

  if (e.key === 'Enter') {
    e.preventDefault();
    submitCommand();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    navigateHistory(-1);
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    navigateHistory(1);
  } else if (e.key === 'Tab') {
    e.preventDefault();
    tabComplete();
  } else if (e.key === 'l' && e.ctrlKey) {
    e.preventDefault();
    cmdClear();
  } else if (e.key === 'c' && e.ctrlKey) {
    e.preventDefault();
    printLine(PROMPT + currentInput + '^C', 'input-echo');
    currentInput = '';
    cursorPos = 0;
    e.target.value = '';
    updateInputDisplay();
    printBlank();
    scrollToBottom();
  } else {
    // Update cursor position after keypress
    setTimeout(() => {
      const input = document.getElementById('terminalInput');
      currentInput = input.value;
      cursorPos = input.selectionStart;
      updateInputDisplay();
    }, 0);
  }
}

function updateInputDisplay() {
  document.getElementById('inputBefore').textContent = currentInput.slice(0, cursorPos);
  document.getElementById('inputAfter').textContent = currentInput.slice(cursorPos);
}

function navigateHistory(dir) {
  const input = document.getElementById('terminalInput');
  if (cmdHistory.length === 0) return;

  historyIndex = Math.max(-1, Math.min(cmdHistory.length - 1, historyIndex + dir));

  if (historyIndex === -1) {
    currentInput = '';
  } else {
    currentInput = cmdHistory[cmdHistory.length - 1 - historyIndex];
  }

  input.value = currentInput;
  cursorPos = currentInput.length;
  input.setSelectionRange(cursorPos, cursorPos);
  updateInputDisplay();
}

function tabComplete() {
  const input = document.getElementById('terminalInput');
  const partial = currentInput.toLowerCase();
  if (!partial) return;

  const matches = COMMAND_NAMES.filter(cmd => cmd.startsWith(partial));

  if (matches.length === 1) {
    currentInput = matches[0];
    input.value = currentInput;
    cursorPos = currentInput.length;
    input.setSelectionRange(cursorPos, cursorPos);
    updateInputDisplay();
  } else if (matches.length > 1) {
    printLine(PROMPT + currentInput, 'input-echo');
    printLine(matches.join('    '), 'dim');
    scrollToBottom();
  }
}

function submitCommand() {
  const raw = currentInput.trim();
  const input = document.getElementById('terminalInput');

  // Echo the command
  printLine(PROMPT + currentInput, 'input-echo');

  currentInput = '';
  input.value = '';
  cursorPos = 0;
  historyIndex = -1;
  updateInputDisplay();

  if (!raw) { printBlank(); scrollToBottom(); return; }

  // Save to history
  if (cmdHistory[cmdHistory.length - 1] !== raw) {
    cmdHistory.push(raw);
    if (cmdHistory.length > 100) cmdHistory.shift();
  }

  printBlank();
  executeCommand(raw);
  printBlank();
  scrollToBottom();
}

function executeCommand(raw) {
  const lower = raw.toLowerCase();

  // Multi-word command check
  if (COMMANDS[lower]) {
    COMMANDS[lower]();
    return;
  }

  // Partial matches (e.g. "sudo hire me" with extra spaces)
  if (lower.startsWith('sudo') && lower.includes('hire')) {
    cmdHireMe();
    return;
  }

  if (lower.startsWith('cat')) {
    if (lower.includes('thought')) { cmdThoughts(); return; }
    if (lower.includes('project')) { printLine('Error: Use the `projects` command instead.', 'error'); return; }
    printLine(`cat: ${raw.slice(4).trim()}: No such file`, 'error');
    return;
  }

  if (lower.startsWith('cd')) {
    const dir = raw.slice(2).trim();
    if (!dir || dir === '~') { printLine('~', 'dim'); return; }
    printLine(`cd: ${dir}: No such directory (you can't leave this terminal that easily)`, 'error');
    return;
  }

  if (lower === 'exit' || lower === 'quit') {
    printLine("There's no exit. Only more commands.", 'dim');
    return;
  }

  if (lower === 'sudo su' || lower === 'sudo bash' || lower === 'sudo sh') {
    printLine('Nice try. Root access denied.', 'error');
    printLine('(Also you probably should not be sudoing into a person.)', 'dim');
    return;
  }

  if (lower.startsWith('rm')) {
    printLine('Permission denied. You cannot delete me.', 'error');
    return;
  }

  if (lower === 'vi' || lower === 'vim' || lower === 'nano' || lower === 'emacs') {
    printLine(`${raw}: editor wars not supported here`, 'warn');
    printLine("(VSCode + Claude Code. That's the setup.)", 'dim');
    return;
  }

  if (lower === 'ping') {
    printLine('PING localhost: 56 bytes of data.', 'dim');
    for (let i = 0; i < 4; i++) {
      printLine(`64 bytes from localhost: icmp_seq=${i} time=${(Math.random()*2+0.3).toFixed(3)} ms`, 'dim');
    }
    return;
  }

  printLine(`command not found: ${raw}`, 'error');
  printLine("Type 'help' to see available commands.", 'dim');
}

// ===== COMMANDS =====

function cmdHelp() {
  printLines([
    { text: '┌─ Available Commands ────────────────────────────────────┐', cls: 'separator' },
    { text: '│                                                          │', cls: 'separator' },
    { text: '│  whoami      → who is Bunny?                            │' },
    { text: '│  projects    → LiquiLink, XevoNet, XevoMind             │' },
    { text: '│  skills      → tech stack overview                      │' },
    { text: '│  stack       → visual stack breakdown                   │' },
    { text: '│  github      → github.com/atharvrs07                    │' },
    { text: '│  liquilink   → link-in-bio platform                     │' },
    { text: '│  xevonet     → full SaaS suite breakdown                │' },
    { text: '│  contact     → reach out                                │' },
    { text: '│  age         → just a number                            │' },
    { text: '│  ls          → list directory                           │' },
    { text: '│  cat thoughts/ → original thoughts from Bunny           │' },
    { text: '│  neofetch    → system info                              │' },
    { text: '│  date        → current time                             │' },
    { text: '│  clear       → clear terminal                           │' },
    { text: '│  sudo hire me → ask nicely                              │' },
    { text: '│                                                          │', cls: 'separator' },
    { text: '│  ↑ / ↓  command history   Tab  autocomplete            │', cls: 'dim' },
    { text: '└──────────────────────────────────────────────────────────┘', cls: 'separator' },
  ]);
}

function cmdWhoami() {
  printLines([
    { text: '  Atharv Raj Sharma (Bunny)', cls: 'bright' },
    { text: '  ─────────────────────────', cls: 'separator' },
    { text: '  Age    : 15', cls: 'dim' },
    { text: '  From   : Bareilly, India', cls: 'dim' },
    { text: '  Status : Building', cls: 'dim' },
    { text: '' },
    { text: '  I build products — LiquiLink and XevoNet.' },
    { text: "  I don't wait to grow up to start." },
    { text: '' },
    { text: '  Founder. Tennis player. Black belt. Builder.', cls: 'dim' },
    { text: "  Right now is the right time.", cls: 'bright' },
  ]);
}

function cmdAge() {
  printLines([
    { text: '  15.', cls: 'bright' },
    { text: '' },
    { text: '  Not a side project.', cls: 'dim' },
    { text: '  Not someday.', cls: 'dim' },
    { text: '  Right now.', cls: 'bright' },
    { text: '' },
    { text: '  Real companies. Real clients. Real products. Real age.', cls: 'dim' },
  ]);
}

function cmdSkills() {
  printLines([
    { text: '  ╔══ Tech Stack ════════════════════╗', cls: 'bright' },
    { text: '' },
    { text: '  Runtime        ██████████  Node.js' },
    { text: '  Framework      ██████████  Express' },
    { text: '  Database       █████████░  SQLite' },
    { text: '  Editor         █████████░  Tiptap' },
    { text: '  Frontend       ████████░░  HTML / CSS / JS' },
    { text: '  Auth           ████████░░  JWT' },
    { text: '  Build          ███████░░░  esbuild' },
    { text: '  Automation     ██████░░░░  Puppeteer' },
    { text: '  Version Ctrl   █████████░  Git' },
    { text: '  AI Dev Tool    ██████████  Claude Code' },
    { text: '' },
    { text: '  ╚══════════════════════════════════╝', cls: 'bright' },
    { text: '' },
    { text: '  Learning: everything needed for the next build.', cls: 'dim' },
  ]);
}

function cmdStack() {
  printLines([
    { text: '  Stack Tree', cls: 'bright' },
    { text: '' },
    { text: '  atharv/', cls: 'accent' },
    { text: '  ├── backend/', cls: 'bright' },
    { text: '  │   ├── Node.js         runtime' },
    { text: '  │   ├── Express         server' },
    { text: '  │   ├── SQLite          database' },
    { text: '  │   └── JWT             auth' },
    { text: '  ├── frontend/', cls: 'bright' },
    { text: '  │   ├── HTML/CSS/JS     vanilla' },
    { text: '  │   └── Tiptap          rich text' },
    { text: '  ├── toolchain/', cls: 'bright' },
    { text: '  │   ├── esbuild         bundler' },
    { text: '  │   └── Puppeteer       automation' },
    { text: '  ├── workflow/', cls: 'bright' },
    { text: '  │   ├── Git             version control' },
    { text: '  │   └── Claude Code     AI dev tool' },
    { text: '  └── next/', cls: 'bright' },
    { text: '      └── Gemini API      (XevoMind - coming)' },
  ]);
}

function cmdProjects() {
  printLines([
    { text: '  ┌─ Projects ─────────────────────────────────────────────┐', cls: 'separator' },
    { text: '' },
    { text: '  01  LiquiLink', cls: 'bright' },
    { text: '      Production-ready link-in-bio platform' },
    { text: '      → liquilink.in', cls: 'accent' },
    { text: '      Real users. Clean UX. Deployed.', cls: 'dim' },
    { text: '' },
    { text: '  02  XevoNet — ecard.xevonet.com', cls: 'bright' },
    { text: '      SaaS suite: Docs, Drive, Spreads, Slides, PDF, CRM' },
    { text: '      → ecard.xevonet.com  (first live product)', cls: 'accent' },
    { text: '      Digital business cards. Real paying clients.', cls: 'dim' },
    { text: '' },
    { text: '  03  XevoMind  [COMING SOON]', cls: 'warn' },
    { text: '      Gemini-powered AI layer for XevoNet Docs' },
    { text: '      Next build. In progress.', cls: 'dim' },
    { text: '' },
    { text: '  └────────────────────────────────────────────────────────┘', cls: 'separator' },
  ]);
}

function cmdGithub() {
  printLines([
    { text: '  → github.com/atharvrs07', cls: 'accent' },
    { text: '  Opening...', cls: 'dim' },
  ]);
  setTimeout(() => window.open('https://github.com/atharvrs07', '_blank'), 400);
}

function cmdLiquilink() {
  printLines([
    { text: '  LiquiLink', cls: 'bright' },
    { text: '  ─────────', cls: 'separator' },
    { text: '' },
    { text: '  A production-ready link-in-bio platform.' },
    { text: '' },
    { text: '  What it does:' },
    { text: '    · One link that holds everything — social, products, contact', cls: 'dim' },
    { text: '    · Custom profiles with clean, minimal design', cls: 'dim' },
    { text: '    · Fast, reliable, deployed', cls: 'dim' },
    { text: '' },
    { text: '  Stack: Node.js / Express / SQLite / JWT / vanilla frontend' },
    { text: '  Status: Live  →  liquilink.in', cls: 'accent' },
    { text: '' },
    { text: '  Not a prototype. Not a school project. A product.', cls: 'dim' },
  ]);
}

function cmdXevonet() {
  printLines([
    { text: '  XevoNet', cls: 'bright' },
    { text: '  ────────', cls: 'separator' },
    { text: '' },
    { text: '  A full SaaS suite. Built from scratch.' },
    { text: '' },
    { text: '  Suite:' },
    { text: '    · Docs       — rich text editing (Tiptap)', cls: 'dim' },
    { text: '    · Drive      — file storage', cls: 'dim' },
    { text: '    · Spreads    — spreadsheets', cls: 'dim' },
    { text: '    · Slides     — presentations', cls: 'dim' },
    { text: '    · PDF        — document export', cls: 'dim' },
    { text: '    · CRM        — client management', cls: 'dim' },
    { text: '' },
    { text: '  First live product: ecard.xevonet.com', cls: 'accent' },
    { text: '    Digital business cards with NFC + QR + analytics' },
    { text: '    Real paying clients. In production.', cls: 'bright' },
    { text: '' },
    { text: '  Next: XevoMind — Gemini AI layer for XevoNet Docs', cls: 'warn' },
    { text: '  The suite keeps growing.', cls: 'dim' },
  ]);
}

function cmdContact() {
  printLines([
    { text: '  Contact', cls: 'bright' },
    { text: '' },
    { text: '  Email     →  atharvrs2010@gmail.com', cls: 'accent' },
    { text: '  GitHub    →  github.com/atharvrs07', cls: 'dim' },
    { text: '  YouTube   →  @grapedot', cls: 'dim' },
    { text: '  Projects  →  liquilink.in / ecard.xevonet.com', cls: 'dim' },
    { text: '' },
    { text: '  Best reached by email. Responses are fast.', cls: 'dim' },
  ]);
}

function cmdLs() {
  printLines([
    { text: '  projects/    skills/    thoughts/    music/    tennis/', cls: 'bright' },
    { text: '  .bashrc      .gitconfig  README.md', cls: 'dim' },
  ]);
}

function cmdThoughts() {
  const thoughts = [
    "\"Being 15 doesn't mean I'm preparing to build things. It means I am building things.\"",
    "\"The gap between idea and shipped product is where most people live. I don't live there.\"",
    "\"Claude Code isn't a crutch. It's an amplifier. There's a difference.\"",
    "\"Everyone says learn first, build later. I learn by building. Always have.\"",
    "\"A paying client at 15 is worth more than any grade. It's real feedback.\"",
    "\"The court teaches you that talent is just the starting point.\"",
  ];

  printLines([
    { text: '  thoughts/', cls: 'bright' },
    { text: '  ──────────', cls: 'separator' },
    { text: '' },
  ]);

  thoughts.forEach((t, i) => {
    printLine(`  ${i + 1}.  ${t}`, 'dim');
    printBlank();
  });

  printLine('  — Atharv Raj Sharma', 'bright');
}

function cmdEasterEgg() {
  printLines([
    { text: '', cls: 'blank' },
    { text: '  [ HIDDEN COMMAND UNLOCKED ]', cls: 'warn' },
    { text: '' },
    { text: '  You found it. Here\'s something real:', cls: 'dim' },
    { text: '' },
    { text: '  I started LiquiLink not because I had a plan,', cls: 'bright' },
    { text: '  but because I was frustrated with existing tools.', cls: 'bright' },
    { text: '  That frustration became a product.', cls: 'bright' },
    { text: '  That product became a company.', cls: 'bright' },
    { text: '' },
    { text: '  The ecard clients aren\'t "early adopters."', cls: 'dim' },
    { text: '  They\'re real businesses paying real money.', cls: 'dim' },
    { text: '  To a 15-year-old.', cls: 'dim' },
    { text: '  That still doesn\'t feel real. But it is.', cls: 'dim' },
    { text: '' },
    { text: '  XevoMind is next. Not because it\'s trendy.', cls: 'bright' },
    { text: '  Because I use XevoNet Docs every day and I know', cls: 'bright' },
    { text: '  exactly what\'s missing.', cls: 'bright' },
    { text: '' },
    { text: '  The best products come from builders who are', cls: 'accent' },
    { text: '  also users. I am both.', cls: 'accent' },
    { text: '' },
    { text: '  — Bunny', cls: 'bright' },
    { text: '' },
  ]);
}

function cmdHireMe() {
  printLines([
    { text: '' },
    { text: '  $ sudo hire me', cls: 'input-echo' },
    { text: '' },
    { text: '  [sudo] password for bunny: ••••••••', cls: 'dim' },
    { text: '' },
    { text: '  Permission granted.', cls: 'bright' },
    { text: '  But let\'s talk first.', cls: 'accent' },
    { text: '' },
    { text: '  → atharvrs2010@gmail.com', cls: 'dim' },
    { text: '' },
    { text: '  Fair warning: I have opinions about architecture,', cls: 'dim' },
    { text: '  ship fast, and already have two companies.', cls: 'dim' },
    { text: '  Make the offer interesting.', cls: 'bright' },
  ]);
}

function cmdNeofetch() {
  const now = new Date();
  printLines([
    { text: '' },
    { text: '         .                   bunny@atharv', cls: 'bright' },
    { text: '        .o+`                 ─────────────', cls: 'bright' },
    { text: '       `ooo/                 OS: Atharv OS v1.0' },
    { text: '      `+oooo:                Age: 15' },
    { text: '     `+oooooo:               Location: Bareilly, India' },
    { text: '     -+oooooo+:              Role: Founder / Builder' },
    { text: '   `/:-:++oooo+:             Companies: LiquiLink, XevoNet' },
    { text: '  `/++++/+++++++:            Shell: Claude Code + Node.js' },
    { text: ' `/++++++++++++++:           Editor: VSCode + Claude' },
    { text: '`/+++ooooooooooooo/`         Racquet: Wilson RF01' },
    { text: './ooosssso++osssssso+`       Belt: Black Belt Dan 1' },
    { text: 'ssssssssssssssssssssssss     Status: Building', cls: 'dim' },
    { text: '' },
    { text: `  Uptime: ${getUptime()}`, cls: 'dim' },
  ]);
}

function cmdPwd() {
  printLine('  /home/bunny', 'dim');
}

function cmdDate() {
  printLine('  ' + new Date().toString(), 'dim');
}

function cmdUptime() {
  printLine(`  ${getUptime()} since boot`, 'dim');
  printLine('  Still building.', 'dim');
}

function cmdMan() {
  printLines([
    { text: '  man: No manual entry. Figure it out.', cls: 'warn' },
    { text: "  (That's usually how it works anyway.)", cls: 'dim' },
  ]);
}

function cmdClear() {
  document.getElementById('terminalOutput').innerHTML = '';
  printBlank();
}

// ===== UTILS =====

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

let bootTime = Date.now();

function getUptime() {
  const secs = Math.floor((Date.now() - bootTime) / 1000);
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}
