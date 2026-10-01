"""
VCF Readiness Tool — Documentation portal client-side JavaScript.
"""

DOCS_JS = r"""
  var activeMatches = [];
  var currentMatchIdx = -1;
  var docPlainTexts = {};

  var STOP_WORDS = {
    "and": 1, "or": 1, "in": 1, "to": 1, "the": 1,
    "a": 1, "an": 1, "of": 1, "for": 1, "with": 1,
    "on": 1, "at": 1, "by": 1, "from": 1, "&": 1, "&&": 1
  };

  // Pre-calculate plain text cache lazily
  function getDocPlainText(key) {
    if (!docPlainTexts[key]) {
      var rawHtml = (DOCS_DATA[key] && DOCS_DATA[key].html) || '';
      var tmp = document.createElement('div');
      tmp.innerHTML = rawHtml;
      docPlainTexts[key] = (tmp.textContent || tmp.innerText || '').toLowerCase();
    }
    return docPlainTexts[key];
  }

  // Tokenize search query with stop word removal for multi-term queries
  function tokenizeQuery(raw) {
    if (!raw) return [];
    var cleaned = raw.replace(/[,;+]/g, ' ').trim();
    if (!cleaned) return [];
    var parts = cleaned.split(/\s+/).map(function(s) { return s.toLowerCase(); });
    if (parts.length > 1) {
      var filtered = parts.filter(function(t) { return !STOP_WORDS[t] && t.length > 0; });
      if (filtered.length > 0) {
        parts = filtered;
      }
    }
    var unique = [];
    parts.forEach(function(t) {
      if (unique.indexOf(t) === -1 && t.length > 0) {
        unique.push(t);
      }
    });
    // Sort descending by length so longer substrings match first in regex alternation
    unique.sort(function(a, b) { return b.length - a.length; });
    return unique;
  }

  // Count matches of tokens in a document
  function countDocMatches(key, tokens) {
    if (!tokens || !tokens.length) return 0;
    var text = getDocPlainText(key);
    var count = 0;
    tokens.forEach(function(tok) {
      if (!tok) return;
      var pos = 0;
      while ((pos = text.indexOf(tok, pos)) !== -1) {
        count++;
        pos += tok.length;
      }
    });
    return count;
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // UI elements
  var root = document.documentElement;
  var themeBtn = document.getElementById('themeToggle');
  var searchInput = document.getElementById('docSearch');
  var searchClearBtn = document.getElementById('searchClear');
  var searchControls = document.getElementById('searchControls');
  var matchCountEl = document.getElementById('searchMatchCount');
  var prevBtn = document.getElementById('searchPrevBtn');
  var nextBtn = document.getElementById('searchNextBtn');
  var contentEl = document.getElementById('docContent');
  var tocBoxEl = document.getElementById('tocBox');
  var tocListEl = document.getElementById('tocList');
  var sidebarListEl = document.getElementById('sidebarList');

  // Theme toggle
  var savedTheme = (function() {
    try { return localStorage.getItem('vcf-theme'); } catch(e) { return null; }
  })();
  var currentTheme = savedTheme || 'dark';

  function applyTheme(t) {
    root.setAttribute('data-theme', t);
    themeBtn.textContent = (t === 'dark') ? '☀️ Light' : '🌙 Dark';
    try { localStorage.setItem('vcf-theme', t); } catch(e) {}
    currentTheme = t;
  }
  applyTheme(currentTheme);
  themeBtn.addEventListener('click', function() {
    applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
  });

  // Render Sidebar
  function renderSidebar(docMatchCounts, isSearching) {
    sidebarListEl.innerHTML = '';
    Object.keys(DOCS_DATA).forEach(function(key) {
      var doc = DOCS_DATA[key];
      var item = document.createElement('a');
      item.className = 'doc-nav-item' + (key === currentDocId ? ' active' : '');
      item.href = '/docs/' + key;
      item.setAttribute('data-doc-id', key);

      var titleDiv = document.createElement('div');
      titleDiv.className = 'doc-item-title';
      titleDiv.innerHTML = '<span>' + (doc.icon || '📄') + '</span> <span>' + doc.title + '</span>';
      item.appendChild(titleDiv);

      var badge = document.createElement('span');
      badge.className = 'doc-badge';
      var count = docMatchCounts ? (docMatchCounts[key] || 0) : 0;
      if (isSearching) {
        badge.textContent = count;
        badge.style.display = 'inline-block';
        if (count === 0 && key !== currentDocId) {
          item.classList.add('search-dim');
        }
      }
      item.appendChild(badge);

      item.addEventListener('click', function(e) {
        e.preventDefault();
        loadDoc(key, true);
      });
      sidebarListEl.appendChild(item);
    });
  }

  // Build Table of Contents from h2 and h3
  function buildTOC() {
    tocListEl.innerHTML = '';
    var headings = contentEl.querySelectorAll('h2, h3');
    if (!headings.length) {
      tocBoxEl.style.display = 'none';
      return;
    }
    tocBoxEl.style.display = 'block';

    headings.forEach(function(h) {
      var id = h.id;
      if (!id) return;
      var li = document.createElement('li');
      li.className = 'toc-' + h.tagName.toLowerCase();
      var a = document.createElement('a');
      a.href = '#' + id;
      a.textContent = h.textContent;
      li.appendChild(a);
      tocListEl.appendChild(li);
    });
  }

  function updateActiveMatch(scroll) {
    if (!activeMatches.length || currentMatchIdx < 0 || currentMatchIdx >= activeMatches.length) {
      matchCountEl.textContent = '0 matches';
      prevBtn.disabled = true;
      nextBtn.disabled = true;
      return;
    }
    prevBtn.disabled = false;
    nextBtn.disabled = false;

    for (var i = 0; i < activeMatches.length; i++) {
      if (i === currentMatchIdx) {
        activeMatches[i].classList.add('active');
      } else {
        activeMatches[i].classList.remove('active');
      }
    }

    matchCountEl.textContent = (currentMatchIdx + 1) + ' of ' + activeMatches.length;

    if (scroll && activeMatches[currentMatchIdx]) {
      activeMatches[currentMatchIdx].scrollIntoView({
        behavior: 'smooth',
        block: 'center'
      });
    }
  }

  function goToNextMatch() {
    if (!activeMatches.length) return;
    currentMatchIdx = (currentMatchIdx + 1) % activeMatches.length;
    updateActiveMatch(true);
  }

  function goToPrevMatch() {
    if (!activeMatches.length) return;
    currentMatchIdx = (currentMatchIdx - 1 + activeMatches.length) % activeMatches.length;
    updateActiveMatch(true);
  }

  function clearSearch() {
    searchInput.value = '';
    performSearch(false);
    searchInput.focus();
  }

  function performSearch(keepActiveIndex) {
    var raw = searchInput.value;
    var tokens = tokenizeQuery(raw);

    // Reset pristine content for current doc first
    var doc = DOCS_DATA[currentDocId] || {};
    contentEl.innerHTML = doc.html || '<p>No content found.</p>';

    if (!tokens.length) {
      activeMatches = [];
      currentMatchIdx = -1;
      searchClearBtn.style.display = 'none';
      searchControls.style.display = 'none';
      buildTOC();
      renderSidebar(null, false);
      return;
    }

    searchClearBtn.style.display = 'block';
    tocBoxEl.style.display = 'none'; // hide TOC during active search

    // Calculate match counts for all documents
    var matchCounts = {};
    var otherDocsWithMatches = [];
    Object.keys(DOCS_DATA).forEach(function(k) {
      var cnt = countDocMatches(k, tokens);
      matchCounts[k] = cnt;
      if (cnt > 0 && k !== currentDocId) {
        otherDocsWithMatches.push({ key: k, count: cnt, doc: DOCS_DATA[k] });
      }
    });

    renderSidebar(matchCounts, true);

    // Highlight matches in current document using TreeWalker
    var pattern = new RegExp('(' + tokens.map(escapeRegex).join('|') + ')', 'gi');

    var walker = document.createTreeWalker(
      contentEl,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function(node) {
          if (!node || !node.parentNode) return NodeFilter.FILTER_REJECT;
          var pName = node.parentNode.nodeName.toUpperCase();
          if (pName === 'SCRIPT' || pName === 'STYLE' || pName === 'MARK') {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      },
      false
    );

    var textNodes = [];
    while (walker.nextNode()) {
      textNodes.push(walker.currentNode);
    }

    textNodes.forEach(function(node) {
      var text = node.nodeValue;
      if (!text || !pattern.test(text)) return;
      pattern.lastIndex = 0;

      var frag = document.createDocumentFragment();
      var lastIdx = 0;
      var match;
      while ((match = pattern.exec(text)) !== null) {
        if (match.index > lastIdx) {
          frag.appendChild(document.createTextNode(text.substring(lastIdx, match.index)));
        }
        var mark = document.createElement('mark');
        mark.className = 'docs-highlight';
        mark.textContent = match[0];
        frag.appendChild(mark);
        lastIdx = pattern.lastIndex;
      }
      if (lastIdx < text.length) {
        frag.appendChild(document.createTextNode(text.substring(lastIdx)));
      }
      if (node.parentNode) {
        node.parentNode.replaceChild(frag, node);
      }
    });

    activeMatches = Array.prototype.slice.call(contentEl.querySelectorAll('.docs-highlight'));

    if (activeMatches.length === 0) {
      searchControls.style.display = 'flex';
      matchCountEl.textContent = '0 matches';
      prevBtn.disabled = true;
      nextBtn.disabled = true;

      // Show no-results banner with cross-document jump links if available
      var banner = document.createElement('div');
      banner.className = 'search-no-results';

      var bTitle = document.createElement('div');
      bTitle.className = 'search-no-results-title';
      bTitle.textContent = 'No matches found in "' + (doc.title || currentDocId) + '"';
      banner.appendChild(bTitle);

      var bDesc = document.createElement('div');
      bDesc.className = 'search-no-results-desc';
      if (otherDocsWithMatches.length > 0) {
        bDesc.textContent = 'The query was found in other guides. Click below to view:';
        banner.appendChild(bDesc);

        var linksWrap = document.createElement('div');
        linksWrap.className = 'search-cross-links';
        otherDocsWithMatches.sort(function(a, b) { return b.count - a.count; });
        otherDocsWithMatches.forEach(function(entry) {
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'search-cross-btn';
          btn.innerHTML = '<span>' + (entry.doc.icon || '📄') + '</span> <span>' + entry.doc.title + '</span> <strong>(' + entry.count + ')</strong>';
          btn.addEventListener('click', function() {
            loadDoc(entry.key, true);
          });
          linksWrap.appendChild(btn);
        });
        banner.appendChild(linksWrap);
      } else {
        bDesc.textContent = 'No matching text found across any of the documentation guides.';
        banner.appendChild(bDesc);
      }

      contentEl.insertBefore(banner, contentEl.firstChild);
      window.scrollTo(0, 0);
      return;
    }

    searchControls.style.display = 'flex';
    if (keepActiveIndex && currentMatchIdx >= 0 && currentMatchIdx < activeMatches.length) {
      // retain index
    } else {
      currentMatchIdx = 0;
    }

    updateActiveMatch(true);
  }

  // Load Document
  function loadDoc(docId, pushState) {
    if (!DOCS_DATA[docId]) docId = 'readme';
    currentDocId = docId;

    var doc = DOCS_DATA[docId];
    document.title = doc.title + ' — VCF Readiness Help';

    if (pushState) {
      history.pushState({docId: docId}, doc.title, '/docs/' + docId);
    }

    contentEl.innerHTML = doc.html || '<p>No content found.</p>';
    buildTOC();

    var currentQuery = searchInput.value;
    if (currentQuery && currentQuery.trim().length > 0) {
      performSearch(false);
    } else {
      renderSidebar(null, false);
      if (window.location.hash) {
        var anchorEl = document.getElementById(window.location.hash.substring(1));
        if (anchorEl) anchorEl.scrollIntoView();
      } else {
        window.scrollTo(0, 0);
      }
    }
  }

  // Handle browser back/forward
  window.addEventListener('popstate', function(e) {
    var docId = (e.state && e.state.docId) ? e.state.docId : parsePathDocId();
    loadDoc(docId, false);
  });

  function parsePathDocId() {
    var path = window.location.pathname.replace(/[/]+$/, '') || '';
    if (path.indexOf('/docs/') === 0) {
      return path.substring(6).split('/')[0] || 'readme';
    }
    return 'readme';
  }

  // Search input listeners
  searchInput.addEventListener('input', function() {
    performSearch(false);
  });

  searchInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) {
        goToPrevMatch();
      } else {
        goToNextMatch();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      clearSearch();
    }
  });

  window.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && searchInput.value && document.activeElement !== searchInput) {
      clearSearch();
    }
  });

  searchClearBtn.addEventListener('click', clearSearch);
  prevBtn.addEventListener('click', goToPrevMatch);
  nextBtn.addEventListener('click', goToNextMatch);

  // Initial load
  loadDoc(currentDocId, false);
"""
