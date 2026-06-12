// ===== TENNIS GAME ENGINE =====

let tennisGame = null;

function initTennis() {
  if (tennisGame) return;
  const canvas = document.getElementById('tennisCanvas');
  if (!canvas) return;
  tennisGame = new TennisGame(canvas);
  tennisGame.start();
}

// ===== TENNIS SCORING =====
const PTS = ['0', '15', '30', '40'];

class TennisScore {
  constructor() { this.reset(); }

  reset() {
    this.playerPts = 0;
    this.bunnyPts = 0;
    this.playerGames = 0;
    this.bunnyGames = 0;
    this.playerSets = 0;
    this.bunnySets = 0;
    this.setHistory = []; // [{p,b}]
    this.deuce = false;
    this.advPlayer = false;
    this.advBunny = false;
    this.matchOver = false;
    this.winner = null;
  }

  pointDisplay() {
    if (this.deuce) return 'DEUCE';
    if (this.advPlayer) return 'AD — YOU';
    if (this.advBunny) return 'AD — BUNNY';
    return `${PTS[this.playerPts]} — ${PTS[this.bunnyPts]}`;
  }

  awardPoint(who) {
    // who: 'player' | 'bunny'
    if (this.matchOver) return null;

    if (this.deuce) {
      if (who === 'player') {
        this.advPlayer = true;
        this.deuce = false;
      } else {
        this.advBunny = true;
        this.deuce = false;
      }
      return null;
    }

    if (this.advPlayer) {
      if (who === 'player') {
        return this._winGame('player');
      } else {
        this.advPlayer = false;
        this.deuce = true;
        return null;
      }
    }

    if (this.advBunny) {
      if (who === 'bunny') {
        return this._winGame('bunny');
      } else {
        this.advBunny = false;
        this.deuce = true;
        return null;
      }
    }

    // Normal scoring
    if (who === 'player') {
      this.playerPts++;
    } else {
      this.bunnyPts++;
    }

    if (this.playerPts >= 3 && this.bunnyPts >= 3) {
      this.playerPts = 3;
      this.bunnyPts = 3;
      this.deuce = true;
      return null;
    }

    if (this.playerPts >= 4) return this._winGame('player');
    if (this.bunnyPts >= 4) return this._winGame('bunny');

    return null;
  }

  _winGame(who) {
    this.playerPts = 0; this.bunnyPts = 0;
    this.deuce = false; this.advPlayer = false; this.advBunny = false;

    if (who === 'player') {
      this.playerGames++;
    } else {
      this.bunnyGames++;
    }

    const setWinner = this._checkSet();
    return setWinner;
  }

  _checkSet() {
    const pg = this.playerGames, bg = this.bunnyGames;
    const maxG = Math.max(pg, bg);
    const diff = Math.abs(pg - bg);

    if (maxG >= 6 && diff >= 2) {
      const who = pg > bg ? 'player' : 'bunny';
      this.setHistory.push({ p: pg, b: bg });
      this.playerGames = 0; this.bunnyGames = 0;

      if (who === 'player') this.playerSets++;
      else this.bunnySets++;

      if (this.playerSets >= 2 || this.bunnySets >= 2) {
        this.matchOver = true;
        this.winner = who;
        return 'match:' + who;
      }
      return 'set:' + who;
    }
    return null;
  }

  gameDisplay() {
    return `${this.playerGames} — ${this.bunnyGames}`;
  }
}

// ===== GAME ENGINE =====

class TennisGame {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.W = 600;
    this.H = 500;
    this.score = new TennisScore();

    this.state = 'ready'; // ready, serving, rally, point, match

    this.ball = { x: 300, y: 350, vx: 0, vy: 0, r: 7, active: false };
    this.player = { x: 300, y: 455, w: 70, h: 12, speed: 7, color: '#38bdf8' };
    this.bunny = { x: 300, y: 45, w: 70, h: 12, speed: 4.2, color: '#e2a04a' };

    this.server = 'player';
    this.rallyCount = 0;
    this.lastHitter = null;
    this.commentary = '';
    this.commentaryTimer = 0;
    this.pointDelay = 0;
    this.serveAnimation = null;
    this.serveBallY = 0;
    this.serveTossed = false;

    this.keys = {};
    this.mouseX = null;
    this.touchActive = false;

    this.resizeCanvas();
    this.bindEvents();
  }

  resizeCanvas() {
    const parent = this.canvas.parentElement;
    const maxW = Math.min(600, parent ? parent.clientWidth - 20 : 600);
    const scale = maxW / 600;
    this.canvas.style.width = `${maxW}px`;
    this.canvas.style.height = `${500 * scale}px`;
    this.canvas.width = 600;
    this.canvas.height = 500;
    this.scale = scale;
  }

  bindEvents() {
    document.addEventListener('keydown', e => {
      this.keys[e.key] = true;
      if (e.key === ' ' && document.getElementById('tab-tennis').classList.contains('active')) {
        e.preventDefault();
        this.handleSpace();
      }
    });
    document.addEventListener('keyup', e => { this.keys[e.key] = false; });

    this.canvas.addEventListener('mousemove', e => {
      const rect = this.canvas.getBoundingClientRect();
      this.mouseX = (e.clientX - rect.left) / this.scale;
    });

    this.canvas.addEventListener('mouseleave', () => { this.mouseX = null; });

    // Touch support
    this.canvas.addEventListener('touchstart', e => {
      e.preventDefault();
      this.touchActive = true;
      const rect = this.canvas.getBoundingClientRect();
      this.mouseX = (e.touches[0].clientX - rect.left) / this.scale;
      if (this.state === 'ready') this.handleSpace();
    }, { passive: false });

    this.canvas.addEventListener('touchmove', e => {
      e.preventDefault();
      const rect = this.canvas.getBoundingClientRect();
      this.mouseX = (e.touches[0].clientX - rect.left) / this.scale;
    }, { passive: false });

    this.canvas.addEventListener('touchend', () => { this.touchActive = false; });

    window.addEventListener('resize', () => this.resizeCanvas());
  }

  handleSpace() {
    if (this.state === 'ready' && this.server === 'player') {
      this.beginServe();
    } else if (this.state === 'match') {
      this.resetMatch();
    }
  }

  start() {
    this.setState('ready');
    this.loop();
  }

  loop() {
    this.update();
    this.draw();
    requestAnimationFrame(() => this.loop());
  }

  setState(s) {
    this.state = s;
    this.updateStatusUI();
  }

  updateStatusUI() {
    const el = document.getElementById('gameStatus');
    if (!el) return;
    if (this.state === 'ready') {
      el.textContent = this.server === 'player' ? 'Press SPACE to serve' : 'Bunny is serving...';
    } else if (this.state === 'match') {
      const w = this.score.winner === 'player' ? 'You win!' : 'Bunny wins!';
      el.textContent = `${w} Press SPACE to play again.`;
    } else {
      el.textContent = '';
    }
    this.updateScoreUI();
  }

  updateScoreUI() {
    const sc = this.score;

    const pPts = document.getElementById('playerPoints');
    const bPts = document.getElementById('bunnyPoints');
    const pGames = document.getElementById('playerGames');
    const bGames = document.getElementById('bunnyGames');
    const pSets = document.getElementById('playerSets');
    const bSets = document.getElementById('bunnySets');
    const setScores = document.getElementById('setScores');
    const commentary = document.getElementById('commentary');

    if (sc.deuce) { if(pPts) pPts.textContent = 'DEU'; if(bPts) bPts.textContent = 'CE'; }
    else if (sc.advPlayer) { if(pPts) pPts.textContent = 'AD'; if(bPts) bPts.textContent = '—'; }
    else if (sc.advBunny) { if(pPts) pPts.textContent = '—'; if(bPts) bPts.textContent = 'AD'; }
    else {
      if(pPts) pPts.textContent = PTS[sc.playerPts] || '0';
      if(bPts) bPts.textContent = PTS[sc.bunnyPts] || '0';
    }

    if(pGames) pGames.innerHTML = `Games: ${sc.playerGames}`;
    if(bGames) bGames.innerHTML = `Games: ${sc.bunnyGames}`;
    if(pSets) pSets.textContent = sc.playerSets;
    if(bSets) bSets.textContent = sc.bunnySets;

    if (setScores) {
      setScores.textContent = sc.setHistory.map(s => `${s.p}–${s.b}`).join(' | ');
    }

    if (commentary && this.commentary) {
      commentary.textContent = this.commentary;
    }
  }

  resetMatch() {
    this.score.reset();
    this.ball.active = false;
    this.server = 'player';
    this.setState('ready');
    this.setCommentary('');
  }

  beginServe() {
    this.setState('serving');
    this.serveTossed = false;
    this.serveBallY = this.player.y - 20;
    this.ball.x = this.player.x;
    this.ball.y = this.player.y - 20;
    this.ball.active = false;

    // Toss up animation
    let tossTime = 0;
    const toss = setInterval(() => {
      tossTime += 16;
      this.ball.y = (this.player.y - 20) - Math.min(60, tossTime * 0.08 * 60);
      if (tossTime > 700) {
        clearInterval(toss);
        this.launchServe();
      }
    }, 16);
  }

  launchServe() {
    const angle = (-Math.PI / 2) + (Math.random() - 0.5) * 0.5;
    const speed = 7 + Math.random() * 2;
    this.ball.vx = Math.cos(angle) * speed * 0.6;
    this.ball.vy = -Math.abs(speed);
    this.ball.active = true;
    this.ball.x = this.player.x;
    this.ball.y = this.player.y - 30;
    this.rallyCount = 0;
    this.lastHitter = 'player';
    this.setState('rally');
  }

  bunnyServe() {
    const speed = 5.5 + Math.random() * 1.5;
    const angle = (Math.PI / 2) + (Math.random() - 0.5) * 0.5;
    this.ball.x = this.bunny.x;
    this.ball.y = this.bunny.y + 20;
    this.ball.vx = Math.cos(angle) * speed * 0.6;
    this.ball.vy = Math.abs(speed);
    this.ball.active = true;
    this.rallyCount = 0;
    this.lastHitter = 'bunny';
    this.setState('rally');
    setTimeout(() => this.updateStatusUI(), 100);
  }

  update() {
    if (this.state === 'rally') {
      this.updateBall();
      this.updatePlayer();
      this.updateBunny();
      this.checkCollisions();
    } else if (this.state === 'ready' && this.server === 'bunny') {
      this.updatePlayer();
      // Bunny serves automatically after delay
      if (!this.bunnyServeTimer) {
        this.bunnyServeTimer = setTimeout(() => {
          this.bunnyServeTimer = null;
          if (this.state === 'ready') this.bunnyServe();
        }, 1500);
      }
    } else if (this.state === 'point') {
      this.pointDelay--;
      if (this.pointDelay <= 0) {
        this.setState('ready');
        if (this.server === 'bunny') {
          // auto trigger
        }
      }
    }

    if (this.commentaryTimer > 0) this.commentaryTimer--;
  }

  updatePlayer() {
    const p = this.player;
    if (this.mouseX !== null) {
      const target = this.mouseX;
      const dx = target - p.x;
      p.x += dx * 0.18;
    } else {
      if (this.keys['ArrowLeft'] || this.keys['a']) p.x -= p.speed;
      if (this.keys['ArrowRight'] || this.keys['d']) p.x += p.speed;
    }
    p.x = Math.max(p.w/2, Math.min(this.W - p.w/2, p.x));
  }

  updateBunny() {
    const b = this.bunny;
    const ball = this.ball;
    if (!ball.active) return;

    // Target the ball, but with reaction delay and imperfect tracking
    const targetX = ball.x + (ball.vx * 5); // lead slightly
    const dx = targetX - b.x;
    const dist = Math.abs(dx);

    // Bunny has reaction lag — only moves when ball is coming toward him
    if (ball.vy < 0) {
      const moveAmt = Math.min(dist, b.speed);
      b.x += Math.sign(dx) * moveAmt;
    } else {
      // Drift back toward center when ball going away
      const centerDrift = (300 - b.x) * 0.03;
      b.x += centerDrift;
    }

    b.x = Math.max(b.w/2, Math.min(this.W - b.w/2, b.x));
  }

  updateBall() {
    const ball = this.ball;
    if (!ball.active) return;
    ball.x += ball.vx;
    ball.y += ball.vy;

    // Side walls
    if (ball.x - ball.r < 30) { ball.x = 30 + ball.r; ball.vx = Math.abs(ball.vx); }
    if (ball.x + ball.r > this.W - 30) { ball.x = this.W - 30 - ball.r; ball.vx = -Math.abs(ball.vx); }

    // Ball out (top or bottom)
    if (ball.y < 10) {
      this.ballOut('bunny-hit-out');
    }
    if (ball.y > this.H - 10) {
      this.ballOut('player-hit-out');
    }
  }

  checkCollisions() {
    const ball = this.ball;
    if (!ball.active) return;

    // Player paddle
    const p = this.player;
    if (
      ball.y + ball.r >= p.y - p.h/2 &&
      ball.y + ball.r <= p.y + p.h/2 + 6 &&
      ball.x >= p.x - p.w/2 - ball.r &&
      ball.x <= p.x + p.w/2 + ball.r &&
      ball.vy > 0
    ) {
      if (this.lastHitter === 'player') {
        this.ballOut('double-bounce');
        return;
      }
      const hitPos = (ball.x - p.x) / (p.w / 2);
      ball.vx = hitPos * 6;
      ball.vy = -(5.5 + Math.random() * 2);
      ball.y = p.y - p.h/2 - ball.r;
      this.lastHitter = 'player';
      this.rallyCount++;
    }

    // Bunny paddle
    const bn = this.bunny;
    if (
      ball.y - ball.r <= bn.y + bn.h/2 &&
      ball.y - ball.r >= bn.y - bn.h/2 - 6 &&
      ball.x >= bn.x - bn.w/2 - ball.r &&
      ball.x <= bn.x + bn.w/2 + ball.r &&
      ball.vy < 0
    ) {
      if (this.lastHitter === 'bunny') {
        this.ballOut('double-bounce');
        return;
      }

      const hitPos = (ball.x - bn.x) / (bn.w / 2);

      // Bunny's shot selection — Federer-style
      // Forehand (ball on right side) = crosscourt = towards player left
      // Backhand (ball on left) = down the line, sometimes mishit
      const isForehand = ball.x > bn.x;
      let newVx;
      if (isForehand) {
        // Crosscourt
        newVx = -Math.abs(hitPos * 5.5) - 1;
      } else {
        // Backhand — usually DTL but occasionally error under pressure
        if (this.rallyCount > 4 && Math.random() < 0.2) {
          // Unforced error — net
          this.awardPoint('player', 'backhand-error');
          return;
        }
        newVx = Math.abs(hitPos * 5) + 0.5;
      }

      ball.vx = newVx + (Math.random() - 0.5) * 1.5;
      ball.vy = 5.5 + Math.random() * 2;
      ball.y = bn.y + bn.h/2 + ball.r;
      this.lastHitter = 'bunny';
      this.rallyCount++;
    }

    // Net collision (y ~= 250)
    const netY = 250;
    if (
      ball.y - ball.r < netY + 8 &&
      ball.y + ball.r > netY - 8 &&
      Math.abs(ball.vy) < 3
    ) {
      // ball barely cleared net or hit it
      if (Math.random() < 0.3) {
        const hitter = ball.vy < 0 ? 'player' : 'bunny';
        this.awardPoint(hitter === 'player' ? 'bunny' : 'player', 'net');
      }
    }
  }

  ballOut(reason) {
    const ball = this.ball;
    ball.active = false;

    let winner;
    if (reason === 'player-hit-out' || reason === 'player-error') {
      winner = 'bunny';
    } else if (reason === 'bunny-hit-out' || reason === 'double-bounce' || reason === 'backhand-error') {
      winner = 'player';
    } else {
      winner = this.lastHitter === 'player' ? 'bunny' : 'player';
    }

    this.awardPoint(winner, reason);
  }

  awardPoint(winner, reason) {
    const setResult = this.score.awardPoint(winner);
    this.updateScoreUI();

    const comments = {
      player: [
        "Good ball. But Bunny's still up.",
        "He let that one go.",
        "Nice shot. Don't get comfortable.",
        "Clean winner. Keep pressing.",
        "That one got through.",
        "Bunny nods. He's seen worse.",
      ],
      bunny: [
        "That was pure Federer.",
        "Clean DTL backhand. Classic.",
        "Bunny's in the zone.",
        "Effortless. Absolutely effortless.",
        "That's what one-handed timing looks like.",
        "He makes it look easy. It isn't.",
      ],
      'backhand-error': [
        "Net! That backhand misfired.",
        "Too much pressure — unforced.",
        "Even Bunny has an off day.",
      ],
    };

    const pool = comments[winner === 'player' && reason === 'backhand-error' ? 'backhand-error' : winner] || [];
    const comment = pool[Math.floor(Math.random() * pool.length)] || '';
    this.setCommentary(comment);

    if (setResult) {
      if (setResult.startsWith('match:')) {
        const matchWinner = setResult.split(':')[1];
        const msg = matchWinner === 'player' ? "You beat Bunny! Incredible." : "Bunny takes the match. Respect it.";
        this.setCommentary(msg);
        this.setState('match');
        return;
      } else if (setResult.startsWith('set:')) {
        const setWinner = setResult.split(':')[1];
        const msg = setWinner === 'player' ? "Set to you. Bunny adjusts." : "Set: Bunny. He tips his racquet.";
        this.setCommentary(msg);
      }
    }

    // Alternate serve
    this.server = winner === 'player' ? 'player' : 'bunny';
    // Actually alternate each game — for simplicity just flip on point win
    this.server = winner;

    this.ball.x = winner === 'player' ? this.player.x : this.bunny.x;
    this.ball.y = winner === 'player' ? this.player.y - 20 : this.bunny.y + 20;

    this.setState('ready');
  }

  setCommentary(text) {
    this.commentary = text;
    const el = document.getElementById('commentary');
    if (el) el.textContent = text;
  }

  // ===== RENDERING =====

  draw() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.W, this.H);
    this.drawCourt();
    this.drawPaddle(this.bunny, '#e2a04a');
    this.drawPaddle(this.player, '#38bdf8');
    this.drawBall();
    this.drawLabels();
    if (this.state === 'match') this.drawMatchOverlay();
    if (this.state === 'ready' && this.server === 'player') this.drawServePrompt();
  }

  drawCourt() {
    const ctx = this.ctx;
    const W = this.W, H = this.H;

    // Background
    ctx.fillStyle = '#1a3a1a';
    ctx.fillRect(0, 0, W, H);

    // Court surface
    ctx.fillStyle = '#2d5a1b';
    ctx.fillRect(30, 30, W - 60, H - 60);

    // Outer lines
    ctx.strokeStyle = 'rgba(255,255,255,0.7)';
    ctx.lineWidth = 2;
    ctx.strokeRect(30, 30, W - 60, H - 60);

    // Service boxes
    const midX = W / 2;
    const netY = H / 2;

    // Service lines (singles)
    ctx.beginPath();
    ctx.moveTo(30, 30 + (H - 60) * 0.21);
    ctx.lineTo(W - 30, 30 + (H - 60) * 0.21);
    ctx.stroke();

    ctx.beginPath();
    ctx.moveTo(30, H - 30 - (H - 60) * 0.21);
    ctx.lineTo(W - 30, H - 30 - (H - 60) * 0.21);
    ctx.stroke();

    // Center service line
    ctx.beginPath();
    ctx.moveTo(midX, 30 + (H - 60) * 0.21);
    ctx.lineTo(midX, H - 30 - (H - 60) * 0.21);
    ctx.stroke();

    // Net
    ctx.fillStyle = 'rgba(200,200,200,0.4)';
    ctx.fillRect(30, netY - 4, W - 60, 8);

    ctx.strokeStyle = 'rgba(255,255,255,0.5)';
    ctx.lineWidth = 1.5;
    for (let x = 30; x < W - 30; x += 8) {
      ctx.beginPath();
      ctx.moveTo(x, netY - 4);
      ctx.lineTo(x + 4, netY + 4);
      ctx.stroke();
    }

    // Net posts
    ctx.fillStyle = '#ccc';
    ctx.fillRect(27, netY - 10, 6, 20);
    ctx.fillRect(W - 33, netY - 10, 6, 20);

    // Center mark (baseline)
    ctx.strokeStyle = 'rgba(255,255,255,0.7)';
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(midX, 30); ctx.lineTo(midX, 40); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(midX, H - 30); ctx.lineTo(midX, H - 40); ctx.stroke();

    // Score panel background at top
    ctx.fillStyle = 'rgba(0,0,0,0.3)';
    ctx.fillRect(0, 0, W, 28);
  }

  drawPaddle(p, color) {
    const ctx = this.ctx;
    const x = p.x, y = p.y, w = p.w, h = p.h;

    // Shadow
    ctx.save();
    ctx.shadowColor = color;
    ctx.shadowBlur = 12;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.roundRect(x - w/2, y - h/2, w, h, 5);
    ctx.fill();
    ctx.restore();

    // Highlight
    ctx.fillStyle = 'rgba(255,255,255,0.25)';
    ctx.beginPath();
    ctx.roundRect(x - w/2 + 3, y - h/2 + 2, w - 6, 3, 2);
    ctx.fill();
  }

  drawBall() {
    const ball = this.ball;
    if (!ball.active && this.state !== 'serving') return;

    const ctx = this.ctx;
    ctx.save();
    ctx.shadowColor = '#ccff00';
    ctx.shadowBlur = 14;
    ctx.fillStyle = '#d4ff00';
    ctx.beginPath();
    ctx.arc(ball.x, ball.y, ball.r, 0, Math.PI * 2);
    ctx.fill();
    // Ball seam
    ctx.strokeStyle = 'rgba(255,255,255,0.3)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(ball.x, ball.y, ball.r - 2, 0.3, Math.PI - 0.3);
    ctx.stroke();
    ctx.restore();
  }

  drawLabels() {
    const ctx = this.ctx;
    // Player label
    ctx.fillStyle = 'rgba(56,189,248,0.8)';
    ctx.font = '500 11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('YOU', this.player.x, this.player.y + 22);

    // Bunny label
    ctx.fillStyle = 'rgba(226,160,74,0.8)';
    ctx.fillText('BUNNY', this.bunny.x, this.bunny.y - 18);

    // Score in court
    ctx.fillStyle = 'rgba(255,255,255,0.6)';
    ctx.font = '500 11px Inter, sans-serif';
    ctx.textAlign = 'center';

    const sc = this.score;
    let pts;
    if (sc.deuce) pts = 'DEUCE';
    else if (sc.advPlayer) pts = 'AD: YOU';
    else if (sc.advBunny) pts = 'AD: BUN';
    else pts = `${PTS[sc.playerPts]} – ${PTS[sc.bunnyPts]}`;

    ctx.fillText(pts, this.W / 2, 18);
  }

  drawMatchOverlay() {
    const ctx = this.ctx;
    ctx.fillStyle = 'rgba(0,0,0,0.65)';
    ctx.fillRect(0, 0, this.W, this.H);

    ctx.fillStyle = this.score.winner === 'player' ? '#38bdf8' : '#e2a04a';
    ctx.font = 'bold 32px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(
      this.score.winner === 'player' ? 'YOU WIN!' : 'BUNNY WINS',
      this.W / 2, this.H / 2 - 20
    );

    ctx.fillStyle = 'rgba(255,255,255,0.5)';
    ctx.font = '14px Inter, sans-serif';
    ctx.fillText('Press SPACE to play again', this.W / 2, this.H / 2 + 20);
  }

  drawServePrompt() {
    const ctx = this.ctx;
    // Draw floating serve prompt near player
    ctx.fillStyle = 'rgba(56,189,248,0.3)';
    ctx.font = '11px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('[ SPACE ] serve', this.player.x, this.player.y - 28);
  }
}

// Polyfill roundRect for older browsers
if (!CanvasRenderingContext2D.prototype.roundRect) {
  CanvasRenderingContext2D.prototype.roundRect = function(x, y, w, h, r) {
    r = Math.min(r, Math.min(w, h) / 2);
    this.beginPath();
    this.moveTo(x + r, y);
    this.lineTo(x + w - r, y);
    this.quadraticCurveTo(x + w, y, x + w, y + r);
    this.lineTo(x + w, y + h - r);
    this.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    this.lineTo(x + r, y + h);
    this.quadraticCurveTo(x, y + h, x, y + h - r);
    this.lineTo(x, y + r);
    this.quadraticCurveTo(x, y, x + r, y);
    this.closePath();
  };
}
