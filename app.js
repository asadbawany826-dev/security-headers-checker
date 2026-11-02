(function () {
  var form = document.getElementById('checkForm');
  var input = document.getElementById('urlInput');
  var btn = document.getElementById('checkBtn');
  var errorBox = document.getElementById('errorBox');
  var results = document.getElementById('results');

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function gradeClass(grade) {
    if (grade.indexOf('A') === 0) return 'g-good';
    if (grade.indexOf('B') === 0 || grade.indexOf('C') === 0) return 'g-mid';
    return 'g-bad';
  }

  function render(data) {
    var badge = document.getElementById('gradeBadge');
    badge.textContent = data.grade;
    badge.className = 'grade ' + gradeClass(data.grade);
    document.getElementById('scoreText').textContent = data.score;
    var bar = document.getElementById('scoreBar');
    bar.style.width = data.score + '%';
    bar.style.background = data.score >= 80 ? 'var(--good)' : data.score >= 55 ? 'var(--weak)' : 'var(--bad)';
    document.getElementById('metaLine').textContent =
      data.finalUrl + '  ·  HTTP ' + data.statusCode + (data.https ? '  ·  HTTPS' : '  ·  plain HTTP (no encryption)');

    var holder = document.getElementById('headerCards');
    holder.innerHTML = '';
    data.results.forEach(function (r) {
      var card = el('div', 'hcard');
      var top = el('div', 'top');
      top.appendChild(el('h3', null, r.name));
      var label = r.status === 'good' ? 'SET' : r.status === 'weak' ? 'WEAK' : 'MISSING';
      top.appendChild(el('span', 'pill ' + r.status, label));
      card.appendChild(top);
      card.appendChild(el('p', null, r.note));
      if (r.value) card.appendChild(el('div', 'val', r.value));
      if (r.fix) {
        var fix = el('p', 'fix');
        var b = el('strong', null, 'Fix: ');
        fix.appendChild(b);
        fix.appendChild(document.createTextNode(r.fix));
        card.appendChild(fix);
      }
      holder.appendChild(card);
    });

    var warnCard = document.getElementById('warningsCard');
    var list = document.getElementById('warningsList');
    list.innerHTML = '';
    if (data.warnings && data.warnings.length) {
      data.warnings.forEach(function (w) { list.appendChild(el('li', null, w)); });
      warnCard.hidden = false;
    } else {
      warnCard.hidden = true;
    }
    results.hidden = false;
  }

  function run(url) {
    errorBox.hidden = true;
    results.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Checking…';
    fetch('/api/check?url=' + encodeURIComponent(url))
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (out) {
        if (!out.ok || out.j.error) throw new Error(out.j.error || 'Something went wrong.');
        render(out.j);
      })
      .catch(function (e) {
        errorBox.textContent = e.message || 'Something went wrong. Try again.';
        errorBox.hidden = false;
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = 'Check';
      });
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var v = input.value.trim();
    if (v) run(v);
  });

  document.querySelectorAll('.chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      input.value = chip.getAttribute('data-url');
      run(input.value);
    });
  });
})();
