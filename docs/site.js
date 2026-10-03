// blue-kakapo site: mobile nav, active-tab, copy button, reveal-on-scroll.
(function () {
  // Mobile nav toggle
  var toggle = document.querySelector(".navtoggle");
  var nav = document.querySelector(".nav nav");
  if (toggle && nav) toggle.addEventListener("click", function () { nav.classList.toggle("open"); });

  // Active tab from current path
  var here = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav nav a[data-page]").forEach(function (a) {
    if (a.getAttribute("data-page") === here) a.classList.add("active");
  });

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
        var t = btn.textContent; btn.textContent = "copied"; setTimeout(function () { btn.textContent = t; }, 1200);
      });
    });
  });

  // Reveal on scroll
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
  }, { threshold: 0.12 });
  document.querySelectorAll(".reveal").forEach(function (el) { io.observe(el); });
})();
