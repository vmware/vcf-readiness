"""Shared, compact saved-credential controls for plugin connection forms."""


def service_picker(
    prefix: str, section: str, endpoint: str, username: str, password: str, source: str = "", port: str = "", role: str = ""
) -> str:
    role_attr = f' data-role="{role}"' if role else ""
    return f'''
<div class="plugin-credential-picker" data-credential-picker="{prefix}" data-section="{section}" data-endpoint="{endpoint}" data-username="{username}" data-password="{password}" data-source="{source}" data-port="{port}"{role_attr}>
  <div class="clr-check-row"><input type="checkbox" id="{prefix}UseSaved" aria-controls="{prefix}SavedFields" aria-expanded="false"><label for="{prefix}UseSaved">Use saved credentials</label></div>
  <div id="{prefix}SavedFields" hidden>
    <div class="clr-form-group"><label class="clr-control-label" for="{prefix}SavedInstance">Saved instance</label><select class="clr-select" id="{prefix}SavedInstance" aria-describedby="{prefix}SavedStatus" disabled><option value="">Select an instance</option></select></div>
    <p id="{prefix}SavedStatus" class="clr-hint" role="status" aria-live="polite">Unlock the Credential Vault to select an instance.</p>
    <div class="flex gap-sm" style="align-items:center;flex-wrap:wrap"><a href="/?credential_kind=vcenter#credential-vault" target="_blank" rel="noopener noreferrer" data-credential-manage="{prefix}">Open Credential Vault in a new tab</a><button type="button" class="btn btn-flat btn-sm" data-credential-refresh="{prefix}">Refresh saved instances</button></div>
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
<div class="clr-form-group" id="vaultServiceRoleGroup"><label class="clr-control-label" for="vaultServiceRole">vCenter role</label><select class="clr-select" id="vaultServiceRole" aria-describedby="vaultServiceRoleHint"><option value="readonly">Read-only</option><option value="administrator">Administrator</option></select><span id="vaultServiceRoleHint" class="clr-hint">Read-only is for Inventory and MTAT. Administrator is for VDT and the vCenter quick check. Saved accounts with no role stay available for read-only use only.</span></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceLabel">Instance name</label><input class="clr-input" id="vaultServiceLabel" maxlength="120" placeholder="Production vCenter" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceEndpoint">HTTPS hostname or URL</label><input class="clr-input" id="vaultServiceEndpoint" maxlength="2048" placeholder="vc-01.rainpole.net" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServiceUsername">Username</label><input class="clr-input" id="vaultServiceUsername" maxlength="256" autocomplete="off"></div>
<div class="clr-form-group"><label class="clr-control-label" for="vaultServicePassword">Password</label><input class="clr-input" id="vaultServicePassword" type="password" maxlength="4096" autocomplete="new-password"></div>
<div class="clr-form-group" id="vaultServiceAuthSourceGroup" hidden><label class="clr-control-label" for="vaultServiceAuthSource">Operations authentication source (optional)</label><input class="clr-input" id="vaultServiceAuthSource" maxlength="256" autocomplete="off"></div>
</div>
<div id="vaultServiceTrustBlock">
<p id="vaultServiceTrustStatus" class="clr-hint" role="status">Review and explicitly trust this vCenter certificate before saving. Its SHA-256 fingerprint is stored with the account in the encrypted vault.</p>
<button type="button" class="btn btn-primary btn-sm" id="vaultServiceReviewCert" aria-describedby="vaultServiceTrustStatus">Review certificate</button>
<div id="vaultServiceCertReview" class="alert alert-info" style="flex-direction:column;align-items:stretch" hidden>
<pre id="vaultServiceCertDetails" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
<p>Compare the SHA-256 fingerprint with vCenter through a trusted channel before accepting it. Reviewing alone does not trust the certificate.</p>
<div><button type="button" class="btn btn-primary btn-sm" id="vaultServiceTrustCert">Trust certificate</button><button type="button" class="btn btn-flat btn-sm" id="vaultServiceCancelCert">Cancel review</button></div>
</div>
</div>
<div class="flex gap-sm" style="flex-wrap:wrap"><button type="button" class="btn btn-primary btn-sm" id="vaultServiceSave" disabled>Save instance</button><button type="button" class="btn btn-flat btn-sm" id="vaultServiceCancel" hidden>Cancel edit</button></div>
<p id="vaultServiceStatus" role="status" aria-live="polite"></p>
<div class="table-responsive" style="max-width:100%;overflow-x:auto"><table class="table"><thead><tr><th scope="col">Service</th><th scope="col">Role</th><th scope="col">Instance</th><th scope="col">Endpoint</th><th scope="col">Account</th><th scope="col">Actions</th></tr></thead><tbody id="vaultServiceRows"></tbody></table></div>
</section>
"""
