// blue-kakapo site — nav, copy, and the "Night Watch" motion layer.
// All motion is gated by prefers-reduced-motion and degrades to static content.
(function () {
  "use strict";
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- Mobile nav toggle ---
  var toggle = document.querySelector(".navtoggle");
  var nav = document.querySelector(".nav nav");
  if (toggle && nav) toggle.addEventListener("click", function () { nav.classList.toggle("open"); });

  // --- Active tab from current path ---
  var here = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav nav a[data-page]").forEach(function (a) {
    if (a.getAttribute("data-page") === here) a.classList.add("active");
  });

  // --- Copy buttons ---
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
        var t = btn.textContent; btn.classList.add("ok"); btn.textContent = "copied ✓";
        setTimeout(function () { btn.textContent = t; btn.classList.remove("ok"); }, 1300);
      });
    });
  });

  // --- Nav shadow once scrolled ---
  var header = document.querySelector("header.nav");
  if (header) {
    var onScroll = function () { header.classList.toggle("scrolled", window.scrollY > 8); };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  // --- Reveal-on-scroll, with per-child stagger for grids/steps ---
  var revealEls = document.querySelectorAll(".reveal");
  if (reduce) {
    revealEls.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var el = e.target;
        var kids = el.querySelectorAll(".grid > *, .steps > *");
        kids.forEach(function (k, i) { k.style.transitionDelay = (i * 70) + "ms"; });
        el.classList.add("in");
        io.unobserve(el);
      });
    }, { threshold: 0.14 });
    revealEls.forEach(function (el) { io.observe(el); });
  }

  // --- Cursor spotlight on cards (pointer-tracked highlight) ---
  if (!reduce && window.matchMedia("(pointer:fine)").matches) {
    document.querySelectorAll(".card, .glass").forEach(function (card) {
      card.addEventListener("pointermove", function (ev) {
        var r = card.getBoundingClientRect();
        card.style.setProperty("--mx", ((ev.clientX - r.left) / r.width * 100) + "%");
        card.style.setProperty("--my", ((ev.clientY - r.top) / r.height * 100) + "%");
      });
    });
  }

  // --- Subtle hero parallax on the aurora + product card ---
  if (!reduce) {
    var aurora = document.querySelector(".aurora");
    var floatEls = document.querySelectorAll("[data-parallax]");
    if (aurora || floatEls.length) {
      var ticking = false;
      window.addEventListener("scroll", function () {
        if (ticking) return; ticking = true;
        window.requestAnimationFrame(function () {
          var y = window.scrollY;
          if (aurora) aurora.style.transform = "translate3d(0," + (y * 0.12) + "px,0)";
          floatEls.forEach(function (el) {
            var s = parseFloat(el.getAttribute("data-parallax")) || 0.05;
            el.style.transform = "translate3d(0," + (-y * s) + "px,0)";
          });
          ticking = false;
        });
      }, { passive: true });
    }
  }

  // --- Count-up for [data-count] when scrolled into view ---
  var counters = document.querySelectorAll("[data-count]");
  if (counters.length) {
    if (reduce) {
      counters.forEach(function (el) { el.textContent = el.getAttribute("data-count"); });
    } else {
      var cio = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          countUp(e.target); cio.unobserve(e.target);
        });
      }, { threshold: 0.5 });
      counters.forEach(function (el) { cio.observe(el); });
    }
  }

  function countUp(el) {
    var target = parseFloat(el.getAttribute("data-count"));
    var suffix = el.getAttribute("data-suffix") || "";
    var dur = 1100, start = performance.now();
    function tick(now) {
      var p = Math.min(1, (now - start) / dur);
      var eased = 1 - Math.pow(1 - p, 3); // easeOutCubic
      var val = target * eased;
      el.textContent = (target % 1 ? val.toFixed(1) : Math.round(val).toLocaleString()) + suffix;
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // --- Interactive triage demo: click an alert → the swarm triages it live ---
  // A faithful, offline mock of the real deterministic first pass (no backend).
  var ALERTS = {
    malicious: {
      caseId: "case_01M4A…C2PB", verdict: "malicious → escalate", conf: 90, cls: "v-red",
      route: "intake → l1 → investigate → route", investigate: true,
      evidence: [
        ["builtin-intel", "198.51.100.23 matches a known-bad indicator", "malicious"],
        ["threat-intel", "malware.example tied to known-malicious activity", "malicious"],
        ["attack-map", "maps to ATT&CK T1071 · command-and-control", "context"],
        ["fusion", "shares an indicator with 2 recent cases", "campaign"],
      ],
    },
    suspicious: {
      caseId: "case_01M4B…9F4A", verdict: "suspicious → escalate", conf: 60, cls: "v-amber",
      route: "intake → l1 → investigate → route", investigate: true,
      evidence: [
        ["heuristics", "alert text mentions: encoded powershell, credential access", "suspicious"],
        ["severity", "max alert severity is medium", "severity"],
        ["attack-map", "maps to ATT&CK T1059 · execution", "context"],
        ["l2", "no benign explanation found in SIEM pivot", "investigation"],
      ],
    },
    benign: {
      caseId: "case_01M4C…71D0", verdict: "false positive → auto-close", conf: 80, cls: "v-green",
      route: "intake → l1 → route", investigate: false,
      evidence: [
        ["builtin-intel", "internal.example is on the benign allowlist", "benign"],
        ["severity", "max alert severity is low", "severity"],
        ["heuristics", "mentions benign markers: scheduled, backup", "benign"],
      ],
    },
  };
  var PIPE_FULL = ["intake", "l1", "intel", "l2", "fusion", "route"];
  var PIPE_SHORT = ["intake", "l1", "route"]; // auto-close path skips investigate

  var console_ = document.querySelector(".demo-console");
  var cards = document.querySelectorAll(".alertcard");
  if (console_ && cards.length) {
    var elCase = console_.querySelector(".dc-case");
    var elBadge = console_.querySelector(".dc-badge");
    var elBar = console_.querySelector(".dc-bar");
    var elEv = console_.querySelector(".dc-evidence");
    var elFinal = console_.querySelector(".dc-final");
    var elFinalText = console_.querySelector(".dc-final-text");
    var elHint = console_.querySelector(".dc-hint");
    var stages = {};
    console_.querySelectorAll(".pstage").forEach(function (s) { stages[s.getAttribute("data-stage")] = s; });
    var timers = [];
    var clear = function () { timers.forEach(clearTimeout); timers = []; };
    var at = function (ms, fn) { timers.push(setTimeout(fn, ms)); };

    function resetConsole() {
      clear();
      Object.keys(stages).forEach(function (k) { stages[k].className = "pstage"; });
      elEv.innerHTML = ""; elBar.style.width = "0%";
      elFinal.classList.remove("show");
      if (elHint) elHint.style.display = "none";
    }

    function run(key) {
      var a = ALERTS[key]; if (!a) return;
      resetConsole();
      elCase.textContent = "CASE · " + a.caseId;
      elBadge.className = "vbadge dc-badge " + a.cls;
      elBadge.textContent = "triaging…";
      var active = a.investigate ? PIPE_FULL : PIPE_SHORT;
      // dim the skipped stages on the auto-close path
      ["intel", "l2", "fusion"].forEach(function (k) {
        if (active.indexOf(k) === -1 && stages[k]) stages[k].classList.add("skip");
      });

      if (reduce) {
        active.forEach(function (k) { stages[k] && stages[k].classList.add("done"); });
        a.evidence.forEach(function (e) { elEv.insertAdjacentHTML("beforeend", evLine(e)); });
        elBar.style.width = a.conf + "%";
        finish(a);
        return;
      }

      var step = 360;
      active.forEach(function (k, i) {
        at(i * step, function () {
          if (!stages[k]) return;
          stages[k].classList.add("active");
          for (var j = 0; j < i; j++) { stages[active[j]] && stages[active[j]].classList.remove("active"); stages[active[j]] && stages[active[j]].classList.add("done"); }
        });
      });
      var afterPipe = active.length * step;
      // stream evidence
      a.evidence.forEach(function (e, i) {
        at(afterPipe + i * 420, function () {
          elEv.insertAdjacentHTML("beforeend", evLine(e));
          var ln = elEv.lastElementChild; if (ln) { requestAnimationFrame(function () { ln.classList.add("show"); }); }
        });
      });
      var afterEv = afterPipe + a.evidence.length * 420;
      at(afterEv, function () {
        active.forEach(function (k) { stages[k] && stages[k].classList.remove("active"); stages[k] && stages[k].classList.add("done"); });
        elBar.style.width = a.conf + "%";
      });
      at(afterEv + 240, function () { finish(a); });
    }

    function finish(a) {
      elBadge.textContent = a.verdict + " · " + a.conf + "%";
      elFinalText.textContent = "ledger verified · " + a.route;
      elFinal.classList.add("show");
    }

    function evLine(e) {
      return '<span class="vline"><span class="src">' + e[0] + "</span>&nbsp; " + e[1] + ' &nbsp;<span class="tag">[' + e[2] + "]</span></span>";
    }

    cards.forEach(function (card) {
      card.addEventListener("click", function () {
        cards.forEach(function (c) { c.classList.remove("active"); c.setAttribute("aria-selected", "false"); });
        card.classList.add("active"); card.setAttribute("aria-selected", "true");
        run(card.getAttribute("data-alert"));
      });
    });
  }
})();
