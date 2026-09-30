(function () {
  var toggle = document.getElementById('navToggle');
  var links = document.getElementById('navLinks');
  if (toggle && links) {
    toggle.addEventListener('click', function () { links.classList.toggle('open'); });
    links.addEventListener('click', function (e) { if (e.target.tagName === 'A') links.classList.remove('open'); });
  }

  function animateCount(el) {
    var target = parseInt(el.getAttribute('data-count'), 10) || 0;
    var start = performance.now(), dur = 1400;
    function step(now) {
      var p = Math.min((now - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.childNodes[0].nodeValue = String(Math.round(target * eased));
      if (p < 1) requestAnimationFrame(step);
      else el.childNodes[0].nodeValue = String(target);
    }
    requestAnimationFrame(step);
  }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (!en.isIntersecting) return;
      en.target.classList.add('in');
      en.target.querySelectorAll('[data-count]').forEach(function (c) {
        if (!c.dataset.done) { c.dataset.done = '1'; animateCount(c); }
      });
      io.unobserve(en.target);
    });
  }, { threshold: 0.18 });
  document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });

  var navAnchors = links ? Array.prototype.slice.call(links.querySelectorAll('a[href^="#"]')) : [];
  var sections = navAnchors.map(function (a) { return document.querySelector(a.getAttribute('href')); }).filter(Boolean);
  function onScroll() {
    if (!sections.length) return;
    var pos = window.scrollY + 120;
    var current = sections[0];
    sections.forEach(function (s) { if (s.offsetTop <= pos) current = s; });
    navAnchors.forEach(function (a) {
      a.classList.toggle('active', current && a.getAttribute('href') === '#' + current.id);
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  var cdTarget = document.getElementById('cd-target');
  if (cdTarget) {
    var target = new Date(cdTarget.getAttribute('data-date')).getTime();
    function tick() {
      var diff = Math.max(0, target - Date.now());
      var d = Math.floor(diff / 86400000);
      var h = Math.floor((diff % 86400000) / 3600000);
      var m = Math.floor((diff % 3600000) / 60000);
      var s = Math.floor((diff % 60000) / 1000);
      var pad = function (n) { return String(n).padStart(2, '0'); };
      document.getElementById('cd-d').textContent = pad(d);
      document.getElementById('cd-h').textContent = pad(h);
      document.getElementById('cd-m').textContent = pad(m);
      document.getElementById('cd-s').textContent = pad(s);
    }
    tick(); setInterval(tick, 1000);
  }

  var form = document.getElementById('contactForm');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var btn = this.querySelector('button');
      btn.textContent = 'Transmission received ✓';
      btn.disabled = true;
      setTimeout(function () { btn.textContent = 'Send transmission'; btn.disabled = false; }, 2600);
      this.reset();
    });
  }
})();
