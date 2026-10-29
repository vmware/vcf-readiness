"""Searchable checkbox-based group selection and explicit page-scoped fleet actions."""

JS_GROUPS = r"""
  var groupCatalog = [], groupTargets = [], groupTargetSelection = new Set();
  var groupChosen = {scanner:new Set(), fleet:new Set()};
  var groupFleetFilters = new Set(), groupFleetSelected = new Set(), groupFleetItems = [];
  var groupFleetOffset = 0, groupFleetTotal = 0, groupRequest = 0, targetRequest = 0;
  var groupSearchTimer, groupTargetTimer, groupResolvedTargetText="";
  function groupEl(id) { return document.getElementById(id); }
  function groupStatus(where, message) { var el=groupEl(where+'GroupStatus'); if(el) el.textContent=message; }
  function groupChips(groups, remove) {
    return (groups||[]).map(function(g) { return '<span class="group-tag">'+esc(g.name)+(remove ? '<button type="button" data-remove-group="'+esc(g.id)+'" aria-label="Remove '+esc(g.name)+' from selection">×</button>' : '')+'</span>'; }).join('');
  }
  function renderGroupChoices(where) {
    var search=groupEl(where+'GroupSearch'), list=groupEl(where+'GroupChoices'), tags=groupEl(where+'GroupTags');
    if(!list) return;
    var active=list.contains(document.activeElement)?document.activeElement.value:null;
    var q=(search.value||'').toLocaleLowerCase(), selected=groupChosen[where];
    list.innerHTML=groupCatalog.filter(function(g){return g.name.toLocaleLowerCase().indexOf(q)!==-1;}).map(function(g){
      return '<label><input type="checkbox" value="'+esc(g.id)+'" '+(selected.has(g.id)?'checked':'')+'> '+esc(g.name)+'</label>';
    }).join('') || '<span class="text-muted">No matching groups. Use + Add group to create one.</span>';
    tags.innerHTML=groupChips(groupCatalog.filter(function(g){return selected.has(g.id);}), true);
    if(active) {var focused=Array.from(list.querySelectorAll('input')).find(function(input){return input.value===active;});if(focused)focused.focus();}
  }
  function renderGroupTargets() {
    var box=groupEl('scannerGroupTargets'); if(!box) return;
    var active=box.contains(document.activeElement)?document.activeElement.value:null;
    box.innerHTML=groupTargets.map(function(h){return '<div class="group-target-row"><label><input type="checkbox" value="'+esc(h.host_id)+'" '+(groupTargetSelection.has(h.host_id)?'checked':'')+'> '+esc(h.target)+'</label>'+groupChips(h.server_groups)+'</div>';}).join('') || '<p class="text-muted">No parsed targets.</p>';
    if(active) {var focused=Array.from(box.querySelectorAll('input')).find(function(input){return input.value===active;});if(focused)focused.focus();}
    var count=groupTargetSelection.size, total=groupTargets.length;
    groupEl('scannerGroupSelection').textContent=count+' of '+total+' parsed targets selected for group changes.';
    var all=groupEl('scannerGroupsSelectAll'); all.checked=!!total && count===total; all.indeterminate=count>0 && count<total;
  }
  function refreshServerGroups() {
    var range=groupEl('rangeInput'), raw=range ? range.value.trim() : '', request=++targetRequest;
    return get('/api/groups'+(raw?'?targets='+encodeURIComponent(raw):'')).then(function(data){
      if(request!==targetRequest) return;
      var prior=new Set(groupTargets.map(function(h){return h.host_id;}));
      var nextCatalog=data.groups||[];
      groupCatalog.forEach(function(old){if(!nextCatalog.some(function(group){return group.id===old.id;}))groupFleetFilters.delete(old.id);});
      groupCatalog=nextCatalog; groupTargets=data.target_hosts||[]; groupResolvedTargetText=raw;
      var available=new Set(groupTargets.map(function(h){return h.host_id;}));
      groupTargetSelection=new Set(Array.from(groupTargetSelection).filter(function(id){return available.has(id);}));
      groupTargets.forEach(function(h){if(!prior.has(h.host_id)) groupTargetSelection.add(h.host_id);});
      ['scanner','fleet'].forEach(function(where){groupChosen[where]=new Set(Array.from(groupChosen[where]).filter(function(id){return groupCatalog.some(function(g){return g.id===id;});}));renderGroupChoices(where);});
      renderGroupTargets(); renderGroupManager();
    }).catch(function(err){if(request===targetRequest) {groupTargets=[];groupTargetSelection.clear();renderGroupTargets();groupStatus('scanner',err.message);}});
  }
  function renderGroupManager() {
    var select=groupEl('fleetManageGroup'); if(!select) return;
    var chosen=select.value;
    select.innerHTML='<option value="">Choose a group</option>'+groupCatalog.map(function(g){return '<option value="'+esc(g.id)+'">'+esc(g.name)+'</option>';}).join('');
    if(groupCatalog.some(function(g){return g.id===chosen;})) select.value=chosen;
  }
  function groupFleetSelectionChanged() {
    groupEl('groupFleetSelection').textContent=groupFleetSelected.size+' hosts selected on this page. Changing filters or pages clears selection.';
    var all=groupEl('groupFleetSelectPage'); all.checked=!!groupFleetItems.length && groupFleetSelected.size===groupFleetItems.length; all.indeterminate=groupFleetSelected.size>0 && groupFleetSelected.size<groupFleetItems.length;
  }
  function renderGroupFleetFilters(facets) {
    var groups=(facets.groups||[]).slice();
    groupCatalog.forEach(function(group){if(!groups.some(function(item){return item.id===group.id;}))groups.push({id:group.id,name:group.name,count:0});});
    groups.sort(function(a,b){return a.name.localeCompare(b.name);});
    groups.push({id:'__ungrouped__',name:'Ungrouped',count:facets.ungrouped||0});
    groupEl('groupFleetFilters').innerHTML=groups.map(function(g){return '<label><input type="checkbox" value="'+esc(g.id)+'" '+(groupFleetFilters.has(g.id)?'checked':'')+'> '+esc(g.name)+' ('+g.count+')</label>';}).join('');
  }
  function refreshGroupFleet(reset) {
    if(!groupEl('groupFleetBody')) return Promise.resolve();
    if(reset) groupFleetOffset=0;
    groupFleetSelected.clear(); groupFleetItems=[]; groupFleetSelectionChanged();
    groupEl("groupFleetBody").innerHTML='<tr><td colspan="3">Loading hosts…</td></tr>';
    groupEl("groupFleetSelectPage").disabled=true;
    var query='?offset='+groupFleetOffset+'&limit=50&search='+encodeURIComponent(groupEl('groupFleetSearch').value.trim());
    groupFleetFilters.forEach(function(id){query+='&group='+encodeURIComponent(id);});
    var request=++groupRequest;
    return get('/api/fleet/index'+query).then(function(data){
      if(request!==groupRequest) return;
      groupFleetItems=data.items||[]; groupFleetTotal=data.filtered_total||0;
      if(groupFleetOffset && groupFleetOffset>=groupFleetTotal) {groupFleetOffset=0;return refreshGroupFleet(false);}
      groupEl("groupFleetSelectPage").disabled=false;
      renderGroupFleetFilters(data.facets||{});
      groupEl('groupFleetCount').textContent=groupFleetTotal+' matching hosts of '+data.total+' total hosts.';
      groupEl('groupFleetBody').innerHTML=groupFleetItems.map(function(h){return '<tr><td><input type="checkbox" data-host-id="'+esc(h.host_id)+'" aria-label="Select '+esc(h.hostname||h.ip)+'"></td><td><strong>'+esc(h.hostname||h.ip)+'</strong><br>'+esc(h.ip)+'<br>'+esc(h.vendor)+' '+esc(h.model)+'</td><td>'+((h.server_groups||[]).length?groupChips(h.server_groups):'<span class="text-muted">Ungrouped</span>')+'</td></tr>';}).join('') || '<tr><td colspan="3">'+(data.total?'No hosts match these filters. Clear filters to see the fleet.':'No current fleet. Import or assemble scans to manage their groups.')+'</td></tr>';
      groupEl('groupFleetPrev').disabled=groupFleetOffset===0;
      groupEl('groupFleetNext').disabled=groupFleetOffset+50>=groupFleetTotal;
      groupEl('groupFleetPage').textContent='Page '+(Math.floor(groupFleetOffset/50)+1)+' of '+Math.max(1,Math.ceil(groupFleetTotal/50));
      groupFleetSelectionChanged();
    }).catch(function(err){groupStatus('fleet',err.message);});
  }
  var groupMutationBusy=false;
  function changeServerGroups(where, body) {
    if(groupMutationBusy) return;
    if(where==='scanner' && groupEl("rangeInput").value.trim()!==groupResolvedTargetText) {
      groupStatus(where,"Targets changed. Wait for the parsed target list before applying groups.");
      refreshServerGroups(); return;
    }
    groupMutationBusy=true; groupStatus(where,'Saving groups and refreshing current reports…');
    document.querySelectorAll('.group-panel button').forEach(function(button){button.disabled=true;});
    if(where==='scanner') {
      body.targets=groupTargets.filter(function(h){return groupTargetSelection.has(h.host_id);}).map(function(h){return h.target;}).join(',');
      delete body.host_ids;
    }
    post('/api/groups',body).then(function(data){
      groupStatus(where,data.warning||'Groups saved.');
      if(data.group) groupChosen[where].add(data.group.id);
      return refreshServerGroups().then(function(){return refreshGroupFleet(false);});
    }).catch(function(err){groupStatus(where,err.message);}).finally(function(){
      groupMutationBusy=false; document.querySelectorAll('.group-panel button').forEach(function(button){button.disabled=false;});
      groupEl('groupFleetPrev').disabled=groupFleetOffset===0; groupEl('groupFleetNext').disabled=groupFleetOffset+50>=groupFleetTotal;
    });
  }
  function selectedGroupHosts(where) {return where==='scanner'?Array.from(groupTargetSelection):Array.from(groupFleetSelected);}
  ['scanner','fleet'].forEach(function(where){
    var search=groupEl(where+'GroupSearch'); if(!search) return;
    search.addEventListener('input',function(){renderGroupChoices(where);});
    groupEl(where+'GroupChoices').addEventListener('change',function(event){var input=event.target;if(input.type!=='checkbox')return;input.checked?groupChosen[where].add(input.value):groupChosen[where].delete(input.value);renderGroupChoices(where);});
    groupEl(where+'GroupTags').addEventListener('click',function(event){var button=event.target.closest('[data-remove-group]');if(!button)return;groupChosen[where].delete(button.dataset.removeGroup);renderGroupChoices(where);search.focus();});
    ['Assign','Remove'].forEach(function(action){groupEl(where+'Groups'+action).addEventListener('click',function(){
      var hosts=selectedGroupHosts(where), ids=Array.from(groupChosen[where]);
      if(!hosts.length || !ids.length){groupStatus(where,'Choose hosts and at least one existing group.');return;}
      changeServerGroups(where,{action:action.toLowerCase(),host_ids:hosts,group_ids:ids});
    });});
    groupEl(where==='scanner'?'scannerAddGroupBtn':'fleetAddGroupBtn').addEventListener('click',function(){
      var name=groupEl(where+'GroupName').value.trim();if(!name){groupStatus(where,'Enter a group name.');groupEl(where+'GroupName').focus();return;}
      changeServerGroups(where,{action:'create',name:name,host_ids:selectedGroupHosts(where)});
    });
  });
  if(groupEl('scannerGroupTargets')) {
    groupEl('scannerGroupTargets').addEventListener('change',function(event){var input=event.target;if(input.type!=='checkbox')return;input.checked?groupTargetSelection.add(input.value):groupTargetSelection.delete(input.value);renderGroupTargets();});
    groupEl('scannerGroupsSelectAll').addEventListener('change',function(){groupTargetSelection=this.checked?new Set(groupTargets.map(function(h){return h.host_id;})):new Set();renderGroupTargets();});
    groupEl('rangeInput').addEventListener('input',function(){clearTimeout(groupTargetTimer);groupTargetTimer=setTimeout(refreshServerGroups,400);});
  }
  if(groupEl('libraryGroupsPanel')) {
    groupEl('groupFleetBody').addEventListener('change',function(event){var input=event.target;if(!input.dataset.hostId)return;input.checked?groupFleetSelected.add(input.dataset.hostId):groupFleetSelected.delete(input.dataset.hostId);groupFleetSelectionChanged();});
    groupEl('groupFleetSelectPage').addEventListener('change',function(){groupFleetSelected=this.checked?new Set(groupFleetItems.map(function(h){return h.host_id;})):new Set();groupEl('groupFleetBody').querySelectorAll('[data-host-id]').forEach(function(input){input.checked=groupFleetSelected.has(input.dataset.hostId);});groupFleetSelectionChanged();});
    groupEl('groupFleetFilters').addEventListener('change',function(event){var input=event.target;if(input.type!=='checkbox')return;input.checked?groupFleetFilters.add(input.value):groupFleetFilters.delete(input.value);refreshGroupFleet(true);});
    groupEl('groupFleetSearch').addEventListener('input',function(){clearTimeout(groupSearchTimer);groupSearchTimer=setTimeout(function(){refreshGroupFleet(true);},250);});
    groupEl('groupFleetClear').addEventListener('click',function(){groupFleetFilters.clear();groupEl('groupFleetSearch').value='';refreshGroupFleet(true);});
    groupEl('groupFleetRefresh').addEventListener('click',function(){refreshServerGroups();refreshGroupFleet(true);});
    groupEl('groupFleetPrev').addEventListener('click',function(){groupFleetOffset=Math.max(0,groupFleetOffset-50);refreshGroupFleet(false);});
    groupEl('groupFleetNext').addEventListener('click',function(){groupFleetOffset+=50;refreshGroupFleet(false);});
    groupEl('fleetManageGroup').addEventListener('change',function(){var id=this.value,g=groupCatalog.find(function(item){return item.id===id;});groupEl('fleetGroupName').value=g?g.name:'';});
    groupEl('fleetRenameGroupBtn').addEventListener('click',function(){changeServerGroups('fleet',{action:'rename',group_id:groupEl('fleetManageGroup').value,name:groupEl('fleetGroupName').value});});
    groupEl('fleetDeleteGroupBtn').addEventListener('click',function(){var id=groupEl('fleetManageGroup').value;if(!id){groupStatus('fleet','Choose a group to delete.');return;}if(confirm('Delete this group and remove all its memberships? Servers remain in the fleet.'))changeServerGroups('fleet',{action:'delete',group_id:id});});
    window.addEventListener('hashchange',function(){if(window.location.hash==='#scan-library'){refreshServerGroups();refreshGroupFleet(true);}});
  }
  refreshServerGroups();
  refreshGroupFleet(true);
"""
