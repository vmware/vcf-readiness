"""Shared structural containment for standalone reports, without changing data."""
import re
from html.parser import HTMLParser

_TEXT_PALETTE = {
    '#64748b': '--text-muted', '#94a3b8': '--text-muted', '#cbd5e1': '--text-muted', '#475569': '--text-muted',
    '#16a34a': '--success', '#22c55e': '--success', '#4ade80': '--success',
    '#ca8a04': '--warning', '#f59e0b': '--warning', '#f97316': '--warning',
    '#dc2626': '--danger', '#ef4444': '--danger', '#f87171': '--danger',
    '#0284c7': '--primary', '#0ea5e9': '--primary', '#60a5fa': '--primary',
}
_TEXT_COLOR = re.compile(r'(?<![\w-])color:\s*(#[\da-fA-F]{6})(?![\da-fA-F])', re.I)
_STYLE = re.compile(r"(\bstyle\s*=\s*)([\"'])(.*?)\2", re.I | re.S)
_FIXED_BACKGROUND = re.compile(r'background(?:-color)?:\s*(?:#|rgb)', re.I)
_VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}
_SCROLL_CLASSES = {'report-table-region', 'report-scroll-region', 'report-scroll', 'report-evidence-body', 'inv-scroll', 'table-scroll', 'job-queue-table', 'memory-finding-table'}


class _ReportLayout(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        wrapped = False
        if tag == 'table' and not any(item[0] in ('table', 'script', 'style', 'pre', 'code', 'textarea') for item in self.stack):
            scrolling = any(
                set(item[1].get('class', '').split()) & _SCROLL_CLASSES
                or any(value in item[1].get('style', '').replace(' ', '') for value in ('overflow:auto', 'overflow:scroll', 'overflow-x:auto', 'overflow-x:scroll'))
                for item in self.stack
            )
            if not scrolling:
                self.parts.append('<div class="report-table-region" role="region" aria-label="Scrollable report table" tabindex="0">')
                wrapped = True
        raw = (self.get_starttag_text() or '')
        protected = any(item[0] in ('svg', 'script', 'style', 'pre', 'code', 'textarea') for item in self.stack)
        fixed_background = any(_FIXED_BACKGROUND.search(item[1].get('style') or '') for item in self.stack)
        style = _STYLE.search(raw)
        if style and not protected and tag not in ('svg', 'code', 'pre', 'input', 'textarea') and not fixed_background and not _FIXED_BACKGROUND.search(style[3]):
            adapted = _TEXT_COLOR.sub(lambda m: 'color:var(' + _TEXT_PALETTE[m[1].lower()] + ')' if m[1].lower() in _TEXT_PALETTE else m[0], style[3])
            raw = raw[:style.start(3)] + adapted + raw[style.end(3):]
        self.parts.append(raw)
        if tag not in _VOID:
            self.stack.append((tag, attrs, wrapped))

    def handle_startendtag(self, tag, attrs):
        self.parts.append(self.get_starttag_text() or '')

    def handle_endtag(self, tag):
        self.parts.append('</' + tag + '>')
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                wrapped = self.stack[index][2]
                del self.stack[index:]
                if wrapped:
                    self.parts.append('</div>')
                break

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        self.parts.append('&#' + name + ';')

    def handle_comment(self, data):
        self.parts.append('<!--' + data + '-->')

    def handle_decl(self, decl):
        self.parts.append('<!' + decl + '>')

    def handle_pi(self, data):
        self.parts.append('<?' + data + '>')


def apply_report_layout(source: str) -> str:
    """Contain outer tables and adapt legacy text colors, preserving evidence/geometry."""
    if '<table' not in source.lower() and not _TEXT_COLOR.search(source):
        return source
    parser = _ReportLayout()
    parser.feed(source)
    parser.close()
    return ''.join(parser.parts)
