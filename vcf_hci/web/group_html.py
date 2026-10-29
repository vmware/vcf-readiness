"""Semantic HTML group controls, styled by the app's shared Clarity tokens."""

GROUP_SCANNER_HTML = """
<details id="scannerGroupsDetails" class="group-disclosure"><summary>+ Server groups <span class="text-muted">(optional)</span></summary>
<fieldset class="group-panel" data-preserve-emojis id="scannerGroupsPanel">
  <legend>Server groups <span class="text-muted">(optional)</span></legend>
  <p class="text-muted">Assign groups to parsed targets before scanning. No discovery probe is required. Groups do not change scan targets or assessment results.</p>
  <label for="scannerGroupSearch">Find existing groups</label>
  <input class="clr-input" id="scannerGroupSearch" type="search" placeholder="Search group names">
  <div id="scannerGroupChoices" class="group-choices" role="group" aria-label="Existing groups"></div>
  <div id="scannerGroupTags" class="group-tags" aria-label="Chosen groups"></div>
  <label for="scannerGroupName">New group name</label>
  <div class="group-toolbar"><input class="clr-input" id="scannerGroupName" maxlength="120" placeholder="For example, Edge cluster"><button id="scannerAddGroupBtn" type="button" class="btn btn-primary">+ Add group</button></div>
  <details open><summary>Choose targets for assignment</summary>
    <label><input id="scannerGroupsSelectAll" type="checkbox"> Select all parsed targets</label>
    <div id="scannerGroupTargets" class="group-targets"></div>
  </details>
  <p id="scannerGroupSelection" class="text-muted">Enter targets above to assign groups.</p>
  <div class="group-toolbar"><button id="scannerGroupsAssign" type="button" class="btn btn-primary">Assign chosen groups</button><button id="scannerGroupsRemove" type="button" class="btn btn-outline">Remove chosen groups</button></div>
  <p id="scannerGroupStatus" role="status" aria-live="polite"></p>
</fieldset>
</details>
"""

GROUP_LIBRARY_HTML = """
<section id="libraryGroupsPanel" class="group-panel" data-preserve-emojis aria-labelledby="libraryGroupsTitle">
  <h2 id="libraryGroupsTitle">Groups in the current fleet</h2>
  <p class="text-muted">Assemble or import scans to manage their hosts here. Search and group filters combine; multiple groups match any membership.</p>
  <div class="group-toolbar"><label for="groupFleetSearch">Search hosts <input class="clr-input" id="groupFleetSearch" type="search"></label><button id="groupFleetClear" type="button" class="btn btn-outline">Clear filters</button><button id="groupFleetRefresh" type="button" class="btn btn-outline">Refresh hosts</button></div>
  <fieldset><legend>Filter groups (match any)</legend><div id="groupFleetFilters" class="group-choices"></div></fieldset>
  <p id="groupFleetCount" role="status"></p>
  <div class="table-scroll"><table class="table"><thead><tr><th><label><input id="groupFleetSelectPage" type="checkbox"> Select this page</label></th><th>Server</th><th>Groups</th></tr></thead><tbody id="groupFleetBody"></tbody></table></div>
  <div class="group-toolbar"><button id="groupFleetPrev" type="button" class="btn btn-outline">Previous page</button><span id="groupFleetPage"></span><button id="groupFleetNext" type="button" class="btn btn-outline">Next page</button></div>
  <p id="groupFleetSelection">0 hosts selected on this page. Changing filters or pages clears selection.</p>
  <label for="fleetGroupSearch">Find groups to assign or remove</label><input class="clr-input" id="fleetGroupSearch" type="search">
  <div id="fleetGroupChoices" class="group-choices" role="group" aria-label="Groups for bulk changes"></div><div id="fleetGroupTags" class="group-tags"></div>
  <div class="group-toolbar"><button id="fleetGroupsAssign" type="button" class="btn btn-primary">Assign chosen groups</button><button id="fleetGroupsRemove" type="button" class="btn btn-outline">Remove chosen groups</button></div>
  <fieldset><legend>Create or manage a group</legend>
    <label for="fleetManageGroup">Existing group</label><select class="clr-select" id="fleetManageGroup"><option value="">Choose a group</option></select>
    <label for="fleetGroupName">Group name</label><input class="clr-input" id="fleetGroupName" maxlength="120">
    <div class="group-toolbar"><button id="fleetAddGroupBtn" type="button" class="btn btn-primary">+ Add group</button><button id="fleetRenameGroupBtn" type="button" class="btn btn-outline">Rename selected group</button><button id="fleetDeleteGroupBtn" type="button" class="btn btn-outline">Delete selected group</button></div>
    <p class="text-muted">Renaming preserves membership. Deleting removes this group from all saved memberships; it does not delete servers.</p>
  </fieldset>
  <p id="fleetGroupStatus" role="status" aria-live="polite"></p>
</section>
"""

GROUP_CSS = """
.group-disclosure{margin-block:12px}
.group-disclosure>summary{cursor:pointer;color:var(--vcf-primary);font-weight:600;padding:8px 0;min-height:32px}
.group-panel .clr-input,.group-panel .clr-select{max-width:32rem}
.group-panel fieldset{margin-block:16px;border:1px solid var(--vcf-border);border-radius:3px;padding:12px;min-width:0}
.group-panel legend{font-size:14px;font-weight:600;padding:0 4px}
.group-panel label{font-size:14px;line-height:1.5}
.group-panel input[type=checkbox]{accent-color:var(--vcf-primary);width:16px;height:16px;flex-shrink:0}
.group-toolbar>label{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.group-toolbar>.clr-input{flex:1 1 240px;min-width:0}
.group-panel p{overflow-wrap:anywhere}

.group-panel { margin-block:1rem; padding:1rem; border:1px solid var(--vcf-border); border-radius:4px; min-width:0; }
.group-panel input[type=search], .group-panel input:not([type]), .group-panel select { max-width:100%; }
.group-toolbar { display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; margin-block:.5rem; }
.group-choices { display:flex; flex-wrap:wrap; gap:.5rem 1rem; max-height:12rem; overflow:auto; padding:.5rem 0; }
.group-choices label { display:inline-flex; align-items:center; gap:.35rem; overflow-wrap:anywhere; }
.group-tags { display:flex; flex-wrap:wrap; gap:.35rem; margin-block:.5rem; }
.group-tag { display:inline-flex; align-items:center; gap:.3rem; border:1px solid var(--vcf-border); border-radius:1rem; padding:.15rem .5rem; font-size:.875rem; color:var(--vcf-text); background:var(--vcf-bg-secondary); overflow-wrap:anywhere; max-width:100%; }
.group-tag button { border:0; background:transparent; color:inherit; cursor:pointer; padding:.1rem .3rem; }
.group-targets { max-height:14rem; overflow:auto; }
.group-target-row { display:flex; flex-wrap:wrap; gap:.4rem; align-items:center; padding:.25rem 0; }
.group-panel .table-scroll { overflow:auto; max-width:100%; }
.group-panel th, .group-panel td { overflow-wrap:anywhere; }
"""
