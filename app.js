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

  function makeCard(title, pillText, status, note, value, findings, fix) {
    var card = el('div', 'hcard');
    var top = el('div', 'top');
    top.appendChild(el('h3', null, title));
    top.appendChild(el('span', 'pill ' + status, pillText));
    card.appendChild(top);
    card.appendChild(el('p', null, note));
    if (value) card.appendChild(el('div', 'val', value));
    if (findings && findings.length) {
      var ul = el('ul', 'findings');
      findings.forEach(function (f) { ul.appendChild(el('li', null, f)); });
      card.appendChild(ul);
    }
    if (fix) {
      var p = el('p', 'fix');
      p.appendChild(el('strong', null, 'Solution: '));
      p.appendChild(document.createTextNode(fix));
      card.appendChild(p);
    }
    return card;
  }

  function render(data) {
    var badge = document.getElementById('gradeBadge');
    badge.textContent = data.grade;
    badge.className = 'grade ' + gradeClass(data.grade);
    document.getElementById('scoreText').textContent = data.score;
    var bar = document.getElementById('scoreBar');
    bar.style.width = data.score + '%';
    bar.style.background = data.score >= 80 ? '#ffffff' : data.score >= 55 ? '#8f8f8f' : '#3f3f3f';
    document.getElementById('metaLine').textContent =
      data.finalUrl + '  ·  HTTP ' + data.statusCode + (data.https ? '  ·  HTTPS' : '  ·  plain HTTP (no encryption)');
    if (typeof data.headerScore === 'number') {
      document.getElementById('headerScoreLine').textContent =
        'Security headers alone: grade ' + data.headerGrade + ' · ' + data.headerScore + '/100';
    }

    var checkHolder = document.getElementById('checkCards');
    checkHolder.innerHTML = '';
    (data.checks || []).forEach(function (c) {
      checkHolder.appendChild(makeCard(c.name, c.pill, c.status, c.note, null, c.findings, c.fix));
    });

    var holder = document.getElementById('headerCards');
    holder.innerHTML = '';
    data.results.forEach(function (r) {
      var label = r.status === 'good' ? 'SET' : r.status === 'weak' ? 'WEAK' : 'MISSING';
      holder.appendChild(makeCard(r.name, label, r.status, r.note, r.value, null, r.fix));
    });

    // Roadmap to 100%: every lost point, and the fix that earns it back.
    var roadCard = document.getElementById('roadmapCard');
    var roadList = document.getElementById('roadmapList');
    var roadIntro = document.getElementById('roadmapIntro');
    roadList.innerHTML = '';
    var items = [];
    (data.checks || []).forEach(function (c) {
      if (c.points < c.maxPoints) {
        items.push({ lost: c.maxPoints - c.points, text: c.name + ': ' + (c.fix || c.note) });
      }
    });
    if (typeof data.headerScore === 'number') {
      var headerLost = 60 - Math.round(data.headerScore * 0.6);
      if (headerLost > 0) {
        items.push({ lost: headerLost, text: 'Security headers: fix the items marked WEAK or MISSING in the Security headers section below — each one shows its own Solution.' });
      }
    }
    items.sort(function (a, b) { return b.lost - a.lost; });
    if (data.score >= 100 || !items.length) {
      roadIntro.textContent = 'This website passes every check — a perfect 100%. Nothing to fix.';
    } else {
      roadIntro.textContent = 'This website is ' + (100 - data.score) + ' points away from 100%. Fix these and it gets there:';
      items.forEach(function (it) {
        var li = el('li');
        li.appendChild(el('strong', null, '−' + it.lost + ' pts '));
        li.appendChild(document.createTextNode('— ' + it.text));
        roadList.appendChild(li);
      });
    }
    roadCard.hidden = false;

    var warnCard = document.getElementById('warningsCard');
    var list = document.getElementById('warningsList');
    list.innerHTML = '';
    if (data.warnings && data.warnings.length) {
      data.warnings.forEach(function (w) {
        var li = el('li');
        if (typeof w === 'string') {
          li.textContent = w;
        } else {
          li.appendChild(document.createTextNode(w.text));
          if (w.solution) {
            var s = el('div', 'warn-solution');
            s.appendChild(el('strong', null, 'Solution: '));
            s.appendChild(document.createTextNode(w.solution));
            li.appendChild(s);
          }
        }
        list.appendChild(li);
      });
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
