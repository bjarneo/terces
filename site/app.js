// terces site. Small enhancements; the page works without them.
"use strict";

(function () {
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  // A demo key, public on purpose. It shows how a fingerprint works. It is
  // not a key that terces uses anywhere.
  var demoKey = new TextEncoder().encode("terces-site-demo-key-not-a-secret!");

  function randomTail(n) {
    var bytes = new Uint8Array(n), out = "";
    crypto.getRandomValues(bytes);
    for (var i = 0; i < n; i++) out += charset[bytes[i] % charset.length];
    return out;
  }

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
  }

  function fingerprint(token) {
    if (!window.crypto || !crypto.subtle) return Promise.resolve(null);
    return crypto.subtle.importKey("raw", demoKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
      .then(function (key) { return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token)); })
      .then(hex)
      .catch(function () { return null; });
  }

  var tails = document.querySelectorAll("[data-token-tail]");
  var fpEl = document.querySelector("[data-fp]");

  function setTails(text) {
    tails.forEach(function (el) { el.textContent = text; });
  }

  function showFingerprint(fp) {
    if (!fpEl) return;
    fpEl.textContent = "";
    if (!fp) {
      fpEl.textContent = "needs a secure context";
      return;
    }
    var head = document.createElement("b");
    head.textContent = fp.slice(0, 12);
    fpEl.appendChild(head);
    fpEl.appendChild(document.createTextNode(fp.slice(12)));
    fpEl.removeAttribute("data-busy");
  }

  // The signature moment: a new fake token settles character by character,
  // then its fingerprint comes into focus.
  function newToken() {
    var tail = randomTail(36);
    var token = "ghp_" + tail;
    if (fpEl) fpEl.setAttribute("data-busy", "");
    var done = fingerprint(token);
    if (reduce) {
      setTails(tail);
      done.then(showFingerprint);
      return;
    }
    // A timer settles the result, so a throttled animation frame in a
    // background tab cannot leave the fingerprint unfinished.
    var start = performance.now(), duration = 520, settled = false;
    function frame(now) {
      if (settled) return;
      var t = Math.min(1, (now - start) / duration);
      var fixed = Math.floor(tail.length * (1 - Math.pow(1 - t, 3)));
      setTails(tail.slice(0, fixed) + randomTail(tail.length - fixed));
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
    var wait = new Promise(function (resolve) { setTimeout(resolve, duration); });
    Promise.all([done, wait]).then(function (r) {
      settled = true;
      setTails(tail);
      showFingerprint(r[0]);
    });
  }

  var button = document.querySelector("[data-new-token]");
  if (button) button.addEventListener("click", newToken);
  newToken();

  // Copy buttons.
  document.querySelectorAll("[data-copy]").forEach(function (box) {
    var btn = box.querySelector(".copy"), code = box.querySelector("code");
    if (!btn || !code) return;
    btn.addEventListener("click", function () {
      var text = code.textContent.replace(/^\$\s*/, "");
      var ok = navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject();
      ok.then(function () {
        btn.setAttribute("data-done", "");
        btn.setAttribute("aria-label", "Copied");
        setTimeout(function () {
          btn.removeAttribute("data-done");
          btn.setAttribute("aria-label", "Copy the command");
        }, 1600);
      }).catch(function () {
        var range = document.createRange();
        range.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
    });
  });

  // Tabs, with arrow keys.
  document.querySelectorAll("[data-tabs]").forEach(function (root) {
    var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { select(tab, false); });
      tab.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
        if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
        if (e.key === "Home") next = tabs[0];
        if (e.key === "End") next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); select(next, true); }
      });
    });
  });

  // The demo video plays muted while it is on screen. It does not play by
  // itself for reduced motion, or after the visitor pauses it.
  var video = document.querySelector("video[data-autoplay]");
  if (video && !reduce && "IntersectionObserver" in window) {
    var ours = false, userPaused = false;
    video.addEventListener("pause", function () { if (!ours) userPaused = true; ours = false; });
    video.addEventListener("play", function () { userPaused = false; });
    new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !userPaused) {
          video.play().catch(function () {});
        } else if (!entry.isIntersecting && !video.paused) {
          ours = true;
          video.pause();
        }
      });
    }, { threshold: 0.5 }).observe(video);
  }

  // The step rail follows the reader.
  var links = Array.prototype.slice.call(document.querySelectorAll(".rail a"));
  var progress = document.querySelector(".rail-progress");
  // On a narrow screen, a sticky bar shows the same step as the rail.
  var barCount = document.querySelector(".stepbar-count");
  var barTitle = document.querySelector(".stepbar-title");
  if (links.length && "IntersectionObserver" in window) {
    var steps = links.map(function (a) { return document.querySelector(a.getAttribute("href")); });
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var i = steps.indexOf(entry.target);
        links.forEach(function (a, j) {
          if (j === i) a.setAttribute("aria-current", "step");
          else a.removeAttribute("aria-current");
        });
        if (progress) progress.style.setProperty("--progress", String((i + 1) / steps.length));
        if (barCount) barCount.textContent = "Step " + (i + 1) + " of " + steps.length;
        if (barTitle) barTitle.textContent = links[i].textContent;
      });
    }, { rootMargin: "-40% 0px -55% 0px" });
    steps.forEach(function (s) { if (s) observer.observe(s); });
  }
})();
