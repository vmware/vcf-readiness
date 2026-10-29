"""Always-on local Clarity icons and scanner density preferences."""
from vcf_hci.ui_clarity import APPEARANCE_JS, UI_ICONS_JS

JS_CLARITY = APPEARANCE_JS + UI_ICONS_JS + r"""
  var scannerDensity = document.getElementById('scannerDensity');
  if (scannerDensity) {
    var density = 'comfortable';
    try { density = localStorage.getItem('vcf-scanner-density') || density; } catch(e) {}
    if (['comfortable','compact'].indexOf(density) < 0) density = 'comfortable';
    function setScannerDensity(value) {
      document.documentElement.setAttribute('data-ui-density',value);
      window.VCFAppearance.density(scannerDensity,value);
      try { localStorage.setItem('vcf-scanner-density',value); } catch(e) {}
    }
    setScannerDensity(density);
    scannerDensity.addEventListener('click',function() {setScannerDensity(scannerDensity.value==='compact'?'comfortable':'compact');});
    window.addEventListener('storage',function(event){if(event.key==='vcf-scanner-density'&&['comfortable','compact'].indexOf(event.newValue)>=0)setScannerDensity(event.newValue);});
  }
"""
