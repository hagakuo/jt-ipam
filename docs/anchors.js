/* 區塊標題本身就是連結（2026-10-01）。
 *
 * 每個有英文 id 的區塊標題整個變成 <a href="#id">：點了網址會帶上 #id（直接複製網址列就能分享），
 * 同時把完整網址複製到剪貼簿；右鍵「複製連結網址」也行。拿到連結的人打開時會自動捲到那一區：
 * 很多區塊不在頂列上，這是唯一能直接指到它們的方法。
 * （第一版是在標題後面加一個「#」，使用者要的是標題本身就是連結。）
 *
 * 錨點名稱寫死在 HTML 裡、一律英文：從中文標題自動產生的話，換個字連結就失效，
 * 而且中文網址在不少聊天軟體裡會被編碼成一長串 %E5%…。
 * 標題自己沒有 id 時，用它所在 section／article 的 id（前提是它是那一區的第一個標題）。
 */
(function () {
  var LABEL = { zh: '這一區的連結（點了會複製）', en: 'Link to this section (click to copy)', ja: 'このセクションへのリンク（クリックでコピー）' };
  var DONE = { zh: '已複製連結', en: 'Link copied', ja: 'リンクをコピーしました' };
  // 卡片類的容器：功能卡片、物件關係卡片、畫面導覽的說明、部署區塊、演講卡片
  var NO_LINK = '.card, .screen-txt, .deploy-zone, .talk';

  function lang() {
    var c = document.body.className;
    return /\blang-zh\b/.test(c) ? 'zh' : /\blang-ja\b/.test(c) ? 'ja' : 'en';
  }

  function targetId(h) {
    if (h.id) return h.id;
    var box = h.parentElement && h.parentElement.closest('section[id], article[id]');
    if (box && box.querySelector('h1, h2, h3, .grp') === h) return box.id;
    return null;
  }

  var css = document.createElement('style');
  css.textContent =
    /* 標題有的是 flex（圖示＋文字），有的是置中的一般區塊：連結本身排成 inline-flex、間距沿用標題的，
       兩種版面看起來都跟原本一樣 */
    '.head-link{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:inherit;' +
    'flex-wrap:wrap;max-width:100%;cursor:pointer;border-radius:4px;transition:color .15s}' +
    '.head-link:hover,.head-link:focus-visible{color:#18a058;outline:none}' +
    '.head-link:focus-visible{box-shadow:0 0 0 2px rgba(24,160,88,.45)}' +
    '.head-link-done{margin-left:.6em;font-size:12px;font-weight:600;color:#18a058;' +
    'white-space:nowrap;opacity:1;transition:opacity .4s}' +
    /* 頂列是 sticky：捲過去時標題不要被它蓋住 */
    'section[id],article[id],h2[id],h3[id],.grp[id]{scroll-margin-top:80px}' +
    '@media(max-width:560px){section[id],article[id],h2[id],h3[id],.grp[id]{scroll-margin-top:124px}}';
  document.head.appendChild(css);

  function copied(h) {
    var old = h.querySelector(':scope > .head-link-done');
    if (old) old.remove();
    var tag = document.createElement('span');
    tag.className = 'head-link-done';
    tag.textContent = DONE[lang()];
    h.appendChild(tag);
    setTimeout(function () { tag.style.opacity = '0'; }, 1100);
    setTimeout(function () { tag.remove(); }, 1600);
  }

  function setup() {
    var heads = document.querySelectorAll('h2, h3, .grp');
    for (var i = 0; i < heads.length; i++) {
      var h = heads[i];
      var id = targetId(h);
      // 標題裡或外面已經有連結的不包（連結不能放在連結裡）；卡片裡的小標題不做連結（使用者要求），
      // 只有區塊的大標題是連結。卡片的 id 照留，舊連結仍然捲得到
      if (!id || h.querySelector('a') || h.closest('a, ' + NO_LINK)) continue;
      var a = document.createElement('a');
      a.className = 'head-link';
      a.href = '#' + id;
      a.setAttribute('aria-label', LABEL.en);
      while (h.firstChild) a.appendChild(h.firstChild);
      h.appendChild(a);
      a.addEventListener('mouseenter', function () { this.title = LABEL[lang()]; });
      a.addEventListener('click', function () {
        var link = this;
        var url = location.href.split('#')[0] + link.getAttribute('href');
        try {
          navigator.clipboard.writeText(url).then(function () { copied(link.parentElement); }, function () {});
        } catch (e) { /* 沒有剪貼簿權限就只換網址 */ }
      });
    }
  }

  // 打開帶 #id 的網址時：頁面設了平滑捲動，從頂端一路滑下去要一兩秒；圖片晚一點才載完
  // 又會把版面往下推 → 載完後直接（不滑動）對準一次
  function realign() {
    var id = decodeURIComponent(location.hash.slice(1));
    var el = id && document.getElementById(id);
    if (el) el.scrollIntoView({ block: 'start', behavior: 'instant' });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setup);
  else setup();
  window.addEventListener('load', function () { if (location.hash) setTimeout(realign, 0); });
})();
