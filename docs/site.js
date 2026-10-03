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
        if (el.hasAttribute("data-verdict")) playVerdict(el);
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

  // --- "Live verdict" showpiece: type evidence lines, fill confidence, tick the ledger ---
  function playVerdict(root) {
    if (reduce) { root.querySelectorAll(".vline,.vfinal").forEach(function (l) { l.classList.add("show"); }); setBar(root, 1); return; }
    var lines = root.querySelectorAll(".vline");
    var i = 0;
    (function next() {
      if (i >= lines.length) {
        setBar(root, 1);
        var fin = root.querySelector(".vfinal");
        if (fin) setTimeout(function () { fin.classList.add("show"); }, 320);
        return;
      }
      lines[i].classList.add("show");
      i++;
      setTimeout(next, 520);
    })();
  }
  function setBar(root, frac) {
    var bar = root.querySelector(".confbar > i");
    if (bar) bar.style.width = Math.round(frac * (parseFloat(bar.getAttribute("data-to")) || 90)) + "%";
  }
})();
