"""Shared Clarity 5.7 presentation and selective offline SVG icon rendering."""
import html
import json
import re
from html.parser import HTMLParser

from vcf_hci.clarity_assets import CLARITY_DARK_CSS, CLARITY_ICON_PATHS

CLARITY_LICENSE_NOTICE = 'MIT License\n\nCopyright (c) 2016-2021 VMware, Inc.  All rights reserved.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.'

# Reviewed UI metaphors only. Unmapped pictographs and user data stay untouched.
UI_EMOJI_ICONS = {
    '🟢': 'success-standard', '🟡': 'warning-standard', '🔴': 'error-standard',
    '🔵': 'info-standard', '🟣': 'info-standard',
    '🧠': 'cpu', '💿': 'hard-disk', '💽': 'hard-drive', '💻': 'computer',
    '🔌': 'connect', '🌐': 'network-globe', '🌡': 'thermometer', '🔑': 'key',
    '📖': 'book', '📘': 'book', '📚': 'book', '🧭': 'compass', '🔖': 'bookmark',
    '🧪': 'flask', '🔬': 'flask', '🛠': 'tools', '🔧': 'wrench', '📐': 'ruler-pencil',
    '🗄': 'rack-server',
    '🔍': 'search', '📁': 'folder-open', '📂': 'folder-open', '📥': 'download',
    '📤': 'upload', '⬇': 'download', '🔒': 'lock', '🔓': 'unlock',
    '❓': 'help-info', '🌙': 'moon', '☀': 'sun', '✅': 'check', '✔': 'check',
    '❌': 'times', '⚠': 'warning-standard', 'ℹ': 'info-standard',
    '🔄': 'refresh', '⚙': 'cog', '🖥': 'computer', '💾': 'storage',
    '📄': 'file', '📊': 'bar-chart', '▶': 'play', '🛑': 'stop',
    '➕': 'plus', '🏷': 'tag', '📋': 'clipboard', '⏱': 'clock',
    '⏳': 'clock', '⚡': 'bolt', '📦': 'bundle', '🛡': 'shield',
    '🏁': 'check-circle', '🗑': 'trash', '✏': 'pencil', '👁': 'eye',
}
UI_LABEL_ICONS = {
    'CPU Architecture': 'cpu', 'Memory': 'memory', 'Memory Channel Interleaving': 'memory',
    'Multi-socket telemetry': 'cpu', 'CPU Fleet Fingerprint': 'cpu', 'Fleet Memory Distribution': 'memory',
    'Fleet Aggregate Raw Resources': 'resource-pool', 'Raw Resources': 'resource-pool',
    'Power Supply': 'power', 'Power Supply Detail': 'power', 'Power Health': 'power',
    'BMC Security Posture': 'shield', 'TPM 2.0 Readiness': 'shield',
    'BIOS Firmware Status': 'cog', 'vSAN Readiness Distribution': 'storage',
    'Drive Endurance Alerts': 'hard-disk', 'SEL Alarm Summary': 'clipboard',
    'ToR Switch Fabric': 'network-switch', 'Host OS Inventory': 'computer',
    'Storage Subsystem': 'storage', 'Storage Inventory': 'storage',
    'Hosts': 'host-group', 'Drives': 'hard-disk', 'NICs': 'connect',
    'BIOS Settings': 'cog', 'Health Alarms': 'info-standard', 'Security': 'shield',
    'Scanner': 'search', 'Scan Library': 'host-group', 'Credential Vault': 'lock',
    'Plugins': 'plugin', 'VDT': 'plugin', 'Saved Profiles': 'bookmark',
    'Credentials': 'key', 'Raw NVMe Storage': 'nvme', 'Physical Memory': 'memory',
}

_UI_MARKS = re.compile('(' + '|'.join(map(re.escape, UI_EMOJI_ICONS)) + r')[\ufe0e\ufe0f]?')


def icon_html(name: str, label: str = '') -> str:
    """Render a trusted local SVG; decorative unless a label is supplied."""
    shape = CLARITY_ICON_PATHS.get(name)
    if shape is None:
        raise ValueError('Unknown Clarity icon: ' + name)
    accessibility = 'role="img" aria-label="' + html.escape(label, quote=True) + '"' if label else 'aria-hidden="true"'
    return ('<svg class="ui-icon" data-clarity-icon="' + html.escape(name, quote=True)
            + '" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" width="18" height="18" fill="currentColor" focusable="false" '
            + accessibility + '>' + shape + '</svg>')


def drive_icon_html(protocol: object, media_type: object) -> str:
    """Choose a drive glyph from reported transport/media; retain adjacent labels."""
    protocol_key = re.sub(r'[^A-Z0-9]', '', str(protocol or '').upper())
    media_key = re.sub(r'[^A-Z0-9]', '', str(media_type or '').upper())
    if protocol_key in {'NVME', 'NVMEXPRESS', 'PCIENVME'}:
        shape = 'nvme'
    elif media_key in {'SSD', 'SOLIDSTATE', 'SOLIDSTATEDRIVE', 'SOLIDSTATEDISK'}:
        shape = 'ssd'
    elif media_key in {'HDD', 'HARDDISK', 'HARDDISKDRIVE', 'ROTATIONAL', 'ROTATING'}:
        shape = 'hard-drive'
    else:
        shape = 'hard-disk'
    return icon_html(shape)


class _UiIconParser(HTMLParser):
    """Preserve markup verbatim; replace only text inside semantic UI labels."""
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        self.parts.append(self.get_starttag_text())
        if tag == 'svg':
            container = self._label_container()
            if container is not None:
                container['_icon_present'] = True
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.parts.append(self.get_starttag_text())

    def handle_endtag(self, tag):
        self.parts.append('</' + tag + '>')
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def _eligible(self):
        if any(tag in {'script', 'style', 'pre', 'code', 'textarea', 'option', 'svg'} or 'pii' in attrs.get('class', '').split() or 'data-preserve-emojis' in attrs for tag, attrs in self.stack):
            return False
        return any(tag in {'button', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'summary', 'legend', 'label', 'th', 'nav'}
                   or 'btn' in attrs.get('class', '').split() or 'ui-label' in attrs.get('class', '').split() or 'badge' in attrs.get('class', '').split() or 'nav-btn' in attrs.get('class', '').split() or 'card-header' in attrs.get('class', '').split()
                   for tag, attrs in self.stack)

    def _label_container(self):
        for tag, attrs in reversed(self.stack):
            if tag in {'h2', 'h3', 'h4'} or 'card-header' in attrs.get('class', '').split() or 'data-inv-view' in attrs or (tag == 'a' and 'data-section-link' in attrs):
                return attrs
        return None

    def handle_data(self, data):
        if self._eligible():
            decorated = _UI_MARKS.sub(lambda m: icon_html(UI_EMOJI_ICONS[m[1]]), data)
            container = self._label_container()
            if decorated != data:
                if container is not None:
                    container['_icon_present'] = True
                data = decorated
            elif container is not None and not container.get('_icon_present') and data.strip() in UI_LABEL_ICONS:
                label = data.strip()
                data = data.replace(label, icon_html(UI_LABEL_ICONS[label]) + ' ' + label, 1)
                container['_icon_present'] = True
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        raw = '&#' + name + ';'
        decoded = html.unescape(raw)
        self.parts.append(icon_html(UI_EMOJI_ICONS[decoded]) if self._eligible() and decoded in UI_EMOJI_ICONS else raw)

    def handle_comment(self, data):
        self.parts.append('<!--' + data + '-->')

    def handle_decl(self, decl):
        self.parts.append('<!' + decl + '>')

    def handle_pi(self, data):
        self.parts.append('<?' + data + '>')


def replace_ui_icons(source: str) -> str:
    """Replace mapped UI decoration, preserving data cells, code and attributes."""
    if not _UI_MARKS.search(source) and '&#' not in source and not any(label in source for label in UI_LABEL_ICONS):
        return source
    parser = _UiIconParser()
    parser.feed(source)
    parser.close()
    return ''.join(parser.parts)


CLARITY_UI_CSS = CLARITY_DARK_CSS + """
:root{--ui-space:8px;--ui-row-padding:8px 12px;--ui-table-font:14px;--ui-control-height:32px}
[data-ui-density='compact']{--ui-row-padding:4px 8px;--ui-table-font:13px;--ui-control-height:28px}
.ui-icon{width:1.125em;height:1.125em;display:inline-block;vertical-align:-.18em;fill:currentColor;flex-shrink:0;overflow:visible;margin-inline-end:.3em}
.ui-icon path,.ui-icon circle,.ui-icon rect{fill:currentColor}
.ui-theme-switch{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}
.ui-switch-track{display:inline-flex;align-items:center;box-sizing:border-box;width:28px;height:16px;border:1px solid currentColor;border-radius:12px;padding:2px}
.ui-switch-track:before{content:'';width:10px;height:10px;background:currentColor;border-radius:50%;transform:translateX(0)}
[aria-checked='true']>.ui-switch-track:before{transform:translateX(12px)}
.ui-density-control{display:inline-flex;align-items:center;gap:8px;font-size:12px}
.ui-density-control select{font:inherit;color:inherit;background:transparent;border:1px solid currentColor;border-radius:3px;padding:3px 6px;max-width:110px}
.ui-density-control option{background:var(--vcf-card,#fff);color:var(--vcf-text,#243746)}
.ui-tag{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--vcf-border,var(--border,#8095a3));border-radius:12px;padding:2px 8px;font-size:12px;max-width:100%;overflow-wrap:anywhere;background:var(--vcf-bg-secondary,var(--th-bg,#edf1f4));color:var(--vcf-text,var(--text,#243746))}
.ui-sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}
"""

SCANNER_CLARITY_CSS = """
:root{color-scheme:light;--vcf-muted:#526777;--vcf-text-muted:#526777;--vcf-border:#b7c4ce;--vcf-control-border:#6c8290;--vcf-success:#146c43;--vcf-warning:#805000;--vcf-danger:#b4232d}
[data-theme='dark']{color-scheme:dark;--vcf-bg:#17242d;--vcf-card:#21333f;--vcf-input-bg:#293f4c;--vcf-select-bg:#293f4c;--vcf-text:#e5edf2;--vcf-muted:#b5c6d1;--vcf-text-muted:#b5c6d1;--vcf-border:#647b8a;--vcf-control-border:#8ba2b1;--vcf-primary:#78c9f0;--vcf-primary-h:#a0dcf7;--vcf-success:#8be0b1;--vcf-warning:#ffd17a;--vcf-danger:#ffabb0;--vcf-bg-secondary:#293f4c;--vcf-bg-subtle:#1b2c36}
body{font-size:14px;line-height:1.5}
.clr-control-label{text-transform:none;letter-spacing:normal;color:var(--vcf-text);font-size:14px;line-height:1.4}
.clr-input,.clr-select,.clr-textarea{border-color:var(--vcf-control-border);font:inherit;min-height:var(--ui-control-height)}
.clr-input::placeholder,.clr-textarea::placeholder{color:var(--vcf-muted);opacity:1}
.clr-hint,.clr-check-hint,.text-xs{font-size:12px;line-height:1.5}
.card-header{font-size:16px;font-weight:600;text-transform:none;letter-spacing:normal}
.btn{min-height:var(--ui-control-height);font-size:14px;line-height:1.4;white-space:normal}
.btn-primary{background:#0072a3;border-color:#0072a3;color:#fff}
.btn-primary:hover:not(:disabled){background:#005674;border-color:#005674}
.btn-danger{background:#b4232d;border-color:#b4232d;color:#fff}
.table,.vcf-cert-table{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--vcf-border);border-radius:3px;font-size:var(--ui-table-font);line-height:1.5}
.table th,.table td,.vcf-cert-table th,.vcf-cert-table td{padding:var(--ui-row-padding);vertical-align:top;text-align:left;border-bottom:1px solid var(--vcf-border)}
.table th,.vcf-cert-table th{color:var(--vcf-text);background:var(--vcf-bg-secondary);font-weight:600}
.table tbody tr:last-child td,.vcf-cert-table tbody tr:last-child td{border-bottom:0}
.table .numeric,.vcf-cert-table .numeric{text-align:right;font-variant-numeric:tabular-nums}
:where(button,a,input,select,textarea,summary,[tabindex]):focus-visible{outline:2px solid var(--vcf-primary);outline-offset:3px}
.log-disclosure{margin-bottom:16px}.log-disclosure>summary{cursor:pointer;font-weight:600;padding:8px 0}
.vcf-modal-dialog{display:flex;flex-direction:column;gap:0}.vcf-modal-header{font-size:18px;line-height:1.4}.vcf-modal-body{min-height:0;overflow:auto}.vcf-modal-footer{display:flex;justify-content:flex-end;flex-wrap:wrap;gap:8px;border-top:1px solid var(--vcf-border)}
@media(max-width:700px){.nav-header{gap:8px}.nav-header .nav-brand{flex-basis:100%}.clr-control-label{font-size:14px}.main-wrap{padding:12px}.card-body{padding:12px}}
"""


def appearance_controls_html(density_id: str) -> str:
    """Render the shared header controls; native buttons work with keyboard input."""
    return (
        '<span class="appearance-controls" role="group" aria-label="Appearance">'
        '<button type="button" id="themeToggle" class="appearance-control" role="switch" '
        'aria-label="Dark mode" aria-checked="true" title="Switch to light mode">'
        + icon_html('moon') + '<span>Dark</span></button>'
        '<button type="button" id="' + html.escape(density_id, quote=True)
        + '" class="appearance-control" aria-label="Compact tables" aria-pressed="false" '
        'title="Use compact table spacing">' + icon_html('two-way-arrows')
        + '<span>Compact</span></button></span>'
    )


APPEARANCE_JS = """
(function(){
 if(window.VCFAppearance)return;
 var icons=__APPEARANCE_ICONS__;
 var api=window.VCFAppearance={};
 api.theme=function(button,dark){
  if(!button)return;
  button.classList.remove('clarity-theme-toggle','ui-theme-switch');button.classList.add('appearance-control');
  button.setAttribute('role','switch');button.setAttribute('aria-label','Dark mode');button.setAttribute('aria-checked',String(dark));
  button.title=dark?'Switch to light mode':'Switch to dark mode';
  button.innerHTML=icons[dark?'moon':'sun']+'<span>'+(dark?'Dark':'Light')+'</span>';
 };
 api.density=function(button,value){
  if(!button)return;var compact=value==='compact';
  button.classList.add('appearance-control');button.setAttribute('aria-label','Compact tables');button.setAttribute('aria-pressed',String(compact));
  button.title=compact?'Use comfortable table spacing':'Use compact table spacing';button.value=compact?'compact':'comfortable';
  button.innerHTML=icons['two-way-arrows']+'<span>Compact</span>';
 };
 api.group=function(theme,density){
  var group=theme.closest('.appearance-controls');
  if(!group){group=document.createElement('span');group.className='appearance-controls';group.setAttribute('role','group');group.setAttribute('aria-label','Appearance');theme.before(group);}
  group.append(theme,density);return group;
 };
})();
""".replace('__APPEARANCE_ICONS__', json.dumps({name: icon_html(name) for name in ('moon', 'sun', 'two-way-arrows')}))

CLARITY_UI_CSS += """
.appearance-controls{display:inline-flex;align-items:center;gap:0;margin-inline-start:auto;vertical-align:middle;float:right;color:var(--text,inherit);white-space:nowrap}
.appearance-controls>button.appearance-control{display:inline-flex;align-items:center;justify-content:center;gap:8px;box-sizing:border-box;min-height:36px;margin:0!important;padding:6px 12px!important;border:0!important;border-inline-start:1px solid var(--appearance-divider,var(--border,currentColor))!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;color:inherit!important;font:600 14px/1.4 'CDS City','Metropolis','Avenir Next','Segoe UI',Arial,sans-serif!important;cursor:pointer;white-space:nowrap}
.appearance-controls>button.appearance-control:hover{background:var(--appearance-hover,var(--th-bg,#edf1f4))!important}
.appearance-controls>button.appearance-control:focus-visible{outline:2px solid var(--appearance-active,var(--primary,#0072a3));outline-offset:-3px}
.appearance-controls>button.appearance-control[aria-pressed='true']{color:var(--appearance-active,var(--primary,#0072a3))!important;text-decoration:underline;text-decoration-thickness:2px;text-underline-offset:5px}
.appearance-controls .ui-icon{width:20px;height:20px;margin:0}
.appearance-controls [data-clarity-icon='two-way-arrows']{transform:rotate(90deg)}
.nav-header .appearance-controls{float:none;--appearance-divider:rgba(255,255,255,.3);--appearance-hover:rgba(255,255,255,.08);--appearance-active:#a9ddf5;color:var(--vcf-nav-text,#e2eaf0)}
@media(max-width:600px){.appearance-controls>button.appearance-control{padding:6px 10px!important}.appearance-controls{max-width:100%}}
@media print{.appearance-controls{display:none!important}}
"""


UI_ICONS_JS = r"""
(function(){
 if(window.VCFIcons)return;
 var shapes=__SHAPES__,marks=__MARKS__,labels=__LABELS__;
 function icon(name){return shapes[name]?'<svg class="ui-icon" data-clarity-icon="'+name+'" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" width="16" height="16" fill="currentColor" focusable="false" aria-hidden="true">'+shapes[name]+'</svg>':'';}
 function excluded(parent){return !parent||!!parent.closest('script,style,pre,code,textarea,input,option,svg,.pii,[data-preserve-emojis]');}
 function labelContainer(parent){return parent.closest('h2,h3,h4,.card-header,[data-inv-view],a[data-section-link]');}
 function enhance(scope){
  if(!scope||(scope.nodeType!==1&&scope.nodeType!==3))return;
  var nodes=[];
  if(scope.nodeType===3)nodes.push(scope);else{var walk=document.createTreeWalker(scope,NodeFilter.SHOW_TEXT),next;while((next=walk.nextNode()))nodes.push(next);}
  nodes.forEach(function(node){
   var parent=node.parentElement;if(excluded(parent))return;
   if(!parent.closest('button,h1,h2,h3,h4,h5,h6,summary,legend,label,th,nav,.btn,.nav-btn,.card-header,.badge,.ui-label'))return;
   var chars=Array.from(node.data),fragment=document.createDocumentFragment(),text='',changed=false;
   function flush(){if(text){fragment.appendChild(document.createTextNode(text));text='';}}
   function append(name){flush();var holder=document.createElement('span');holder.innerHTML=icon(name);if(holder.firstChild)fragment.appendChild(holder.firstChild);changed=true;}
   for(var i=0;i<chars.length;i++){var shape=marks[chars[i]];if(!shape){text+=chars[i];continue;}append(shape);if(chars[i+1]==='\ufe0f'||chars[i+1]==='\ufe0e')i++;}
   if(changed){flush();node.replaceWith(fragment);return;}
   var label=node.data.trim(),container=labelContainer(parent);
   if(container&&labels[label]&&!container.querySelector('svg,.ui-icon')&&!/^[\u{1f000}-\u{1faff}]/u.test(label)){
    var holder=document.createElement('span');holder.innerHTML=icon(labels[label]);fragment.append(document.createTextNode(node.data.slice(0,node.data.indexOf(label))),holder.firstChild,document.createTextNode(' '+label+node.data.slice(node.data.indexOf(label)+label.length)));node.replaceWith(fragment);
   }
  });
 }
 var observer;
 function watch(){observer.observe(document.body,{childList:true,subtree:true,characterData:true});}
 window.VCFIcons={html:icon,enhance:enhance};
 function start(){enhance(document.body);observer=new MutationObserver(function(records){observer.disconnect();records.forEach(function(record){if(record.type==='characterData')enhance(record.target);else record.addedNodes.forEach(enhance);});watch();});watch();}
 if(document.body)start();else document.addEventListener('DOMContentLoaded',start);
})();
""".replace('__SHAPES__', json.dumps(CLARITY_ICON_PATHS)).replace('__MARKS__', json.dumps(UI_EMOJI_ICONS, ensure_ascii=False)).replace('__LABELS__', json.dumps(UI_LABEL_ICONS))


CLARITY_UI_CSS += """
.ui-icon{width:16px;height:16px;vertical-align:-.18em;flex-shrink:0;margin-inline-end:4px}
h2>.ui-icon,h3>.ui-icon,h4>.ui-icon,.card-header>.ui-icon{width:18px;height:18px}
.appearance-controls .ui-icon{width:20px;height:20px;margin:0}
.report-media{display:inline-flex;align-items:center;gap:4px;vertical-align:top;white-space:normal}
.report-media>.ui-icon{margin:0}
.report-media-label{min-width:0;overflow-wrap:anywhere}
"""
