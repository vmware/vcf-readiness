"""Shared, compact saved-credential controls for plugin connection forms."""


def service_picker(
    prefix: str, section: str, endpoint: str, username: str, password: str, source: str = "", port: str = ""
) -> str:
    return f'''
<div class="plugin-credential-picker" data-credential-picker="{prefix}" data-section="{section}" data-endpoint="{endpoint}" data-username="{username}" data-password="{password}" data-source="{source}" data-port="{port}">
  <div class="clr-check-row"><input type="checkbox" id="{prefix}UseSaved" aria-controls="{prefix}SavedFields" aria-expanded="false"><label for="{prefix}UseSaved">Use saved credentials</label></div>
  <div id="{prefix}SavedFields" hidden>
    <div class="clr-form-group"><label class="clr-control-label" for="{prefix}SavedInstance">Saved instance</label><select class="clr-select" id="{prefix}SavedInstance" aria-describedby="{prefix}SavedStatus" disabled><option value="">Select an instance</option></select></div>
    <p id="{prefix}SavedStatus" class="clr-hint" role="status" aria-live="polite">Unlock the Credential Vault to select an instance.</p>
    <div class="flex gap-sm" style="align-items:center;flex-wrap:wrap"><a href="#credential-vault" data-section-link="credential-vault" data-credential-manage="{prefix}">Unlock vault or add an instance</a><button type="button" class="btn btn-flat btn-sm" data-credential-refresh="{prefix}">Refresh saved instances</button></div>
  </div>
</div>
'''


SERVICE_CREDENTIALS_PANEL = """
<section aria-labelledby="serviceCredentialHeading" id="vaultServiceSection">
<h2 id="serviceCredentialHeading">vCenter &amp; VCF Operations</h2>
<p>Saved service accounts for plugins. vCenter SSO and Operations credentials are separate from BMC and appliance SSH accounts. Passwords stay in the encrypted vault.</p>
<p><a id="vaultServiceReturn" href="#plugins" data-section-link="plugins">Return to Plugins</a></p>
<div class="form-grid">
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceKind">Service</label><select class="clr-select" id="vaultServiceKind"><option value="vcenter">vCenter</option><option value="operations">VCF Operations</option></select></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceLabel">Instance name</label><input class="clr-input" id="vaultServiceLabel" maxlength="120" placeholder="Production vCenter" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceEndpoint">HTTPS hostname or URL</label><input class="clr-input" id="vaultServiceEndpoint" maxlength="2048" placeholder="vc-01.rainpole.net" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceUsername">Username</label><input class="clr-input" id="vaultServiceUsername" maxlength="256" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServicePassword">Password</label><input class="clr-input" id="vaultServicePassword" type="password" maxlength="4096" autocomplete="new-password"></div>
<div class="clr-form-group" id="vaultServiceAuthSourceGroup" hidden><label class="clr-control-label" for="vaultServiceAuthSource">Operations authentication source (optional)</label><input class="clr-input" id="vaultServiceAuthSource" maxlength="256" autocomplete="off"></div>
</div>
<div class="flex gap-sm" style="flex-wrap:wrap"><button type="button" class="btn btn-primary btn-sm" id="vaultServiceSave">Save instance</button><button type="button" class="btn btn-flat btn-sm" id="vaultServiceCancel" hidden>Cancel edit</button></div>
<p id="vaultServiceStatus" role="status" aria-live="polite"></p>
<div class="table-responsive" style="max-width:100%;overflow-x:auto"><table class="table"><thead><tr><th scope="col">Service</th><th scope="col">Instance</th><th scope="col">Endpoint</th><th scope="col">Account</th><th scope="col">Actions</th></tr></thead><tbody id="vaultServiceRows"></tbody></table></div>
</section>
"""
