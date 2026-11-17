"""Finalize session-owned wizard jobs into the completed hardware scan directory."""
import base64
import json
import os
from pathlib import Path
from typing import Any

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.logging_utils import sanitize_filename
from vcf_hci.report.mtat_panel import render_mtat_panel, render_upstream_panel, standalone_report


def save_artifacts(handler: Any) -> None:
    from vcf_hci.web.mtat_api import export_zip as mtat_zip
    from vcf_hci.web.scan_worker import _regenerate_fleet_artifacts, _state, _state_lock
    from vcf_hci.web.vinv_api import export_zip as inventory_zip
    from vcf_hci.web.vinv_api import server_state
    session = handler._vinv_guard()
    if not session:
        return
    data = handler._read_json_body()
    if not isinstance(data, dict):
        handler._send_json({'error': 'Expected a JSON object.'}, 400)
        return
    snapshot, assessments = None, ()
    for kind in ('vinv', 'mtat'):
        requested = data.get(kind + '_job_id')
        if not requested:
            continue
        job = getattr(handler.server, kind + '_job', None)
        if not job or job.get('id') != requested or job.get('session') != session or job.get('stage') != 'done':
            handler._send_json({'error': 'The selected ' + kind + ' job is unavailable or incomplete.'}, 409)
            return
        if kind == 'vinv':
            _, library = server_state(handler.server)
            snapshot = library.get(session, job.get('entry_id', ''))
            if snapshot is None:
                handler._send_json({'error': 'Inventory result expired.'}, 409)
                return
        else:
            assessments = tuple(job.get('assessments') or (job['assessment'],))
    upstream_payload = None
    upstream_worker = None
    upstream_identity = None
    if data.get('upstream_job_id') or data.get('upstream_dataset') or data.get('upstream_dataset_id'):
        try:
            upstream_worker = handler.server.mtat_runtime.get(session)
            if data.get('upstream_job_id'):
                status = upstream_worker.request('jobs.status', {'id': data['upstream_job_id']})
                datasets = [task['dataset_id'] for task in status.get('tasks', [])
                            if task.get('status') == 'completed' and task.get('dataset_id')]
                if not datasets:
                    raise ValueError('No completed upstream task is available.')
                upstream_payload = {'datasets': datasets}
            else:
                upstream_payload = {'dataset': data.get('upstream_dataset') or data['upstream_dataset_id']}
            upstream_identity = {'package': upstream_worker.manifest['version'],
                                 'workspace_id': handler.server.mtat_runtime.workspaces[session],
                                 'job_id': data.get('upstream_job_id')}
        except (ValueError, OSError):
            handler._send_json({'error': 'The selected upstream result is unavailable; open its saved workspace and retry.'}, 409)
            return
    if snapshot is None and not assessments and upstream_payload is None:
        handler._send_json({'error': 'Select completed Inventory or MTAT jobs.'}, 400)
        return
    hardware = bool(data.get('scan_id'))
    with _state_lock:
        conflict = None
        if hardware and data['scan_id'] != _state.get('scan_id'):
            conflict = ('scan_changed', 'The hardware scan was replaced. Check Scanner for the active run, then reset the wizard before starting new targets.')
        elif _state.get('running'):
            conflict = ('scan_running', 'Hardware collection is still running. Wait for it to finish before saving combined reports.')
        elif _state.get('_fleet_worker_active') or _state.get('_fleet_operation'):
            conflict = ('reports_busy', 'Hardware reports are still being saved. Wait for report saving to finish, then retry.')
        if conflict:
            handler._send_json({'error_code': conflict[0], 'error': conflict[1]}, 409)
            return
        outdir = _state.get('outdir') if hardware else None
        results = list(_state.get('results') or []) if hardware else []
        failed = list(_state.get('failed_hosts') or []) if hardware else []
        if not hardware:
            import uuid

            from vcf_hci.logging_utils import normalize_output_dir
            outdir = os.path.join(normalize_output_dir(data.get('output_dir')), sanitize_filename('Assessment_' + uuid.uuid4().hex))
        if not outdir or (hardware and not os.path.isdir(outdir)):
            handler._send_json({'error': 'The completed scan directory is unavailable.'}, 409)
            return
        _state['_fleet_worker_active'] = True
    try:
        folder = Path(outdir)
        folder.mkdir(parents=True, exist_ok=True)
        written = []
        def write(name: str, content: bytes) -> None:
            safe = sanitize_filename(name)
            (folder / safe).write_bytes(content)
            written.append(safe)
        panel = None
        matched = None
        if snapshot is not None:
            from vcf_hci.plugins.vinv.reconcile import reconcile_fleet
            matched = reconcile_fleet(results, snapshot).matched_count if hardware else None
            write('vsphere_inventory.zip', inventory_zip(snapshot))
            from vcf_hci.plugins.vinv.xlsx_io import render_vinv_xlsx
            write('vsphere_inventory.xlsx', render_vinv_xlsx(snapshot))
        if assessments:
            panel = render_mtat_panel(assessments)
            write('mtat_assessment.html', standalone_report(panel).encode('utf-8'))
            write('mtat_assessment.zip', mtat_zip(assessments[0], TOOL_VERSION, assessments))
        if upstream_payload is not None and upstream_worker is not None:
            calculation = upstream_worker.request('calculate', upstream_payload)
            panel = render_upstream_panel(calculation)
            for format_, filename in (('html', 'mtat_upstream_assessment.html'), ('zip', 'mtat_upstream_assessment.zip')):
                exported = upstream_worker.request('export', dict(upstream_payload, format=format_))
                raw = base64.b64decode(exported.get('content_b64') or exported.get('content_base64') or '', validate=True)
                if not raw or len(raw) > 32 * 1024 * 1024:
                    raise ValueError('Upstream export byte limit exceeded.')
                write(filename, raw)
        provenance = {'scan_id': data.get('scan_id'), 'vinv_job_id': data.get('vinv_job_id'),
                      'mtat_job_id': data.get('mtat_job_id'), 'bmc_hosts': len(results),
                      'inventory_matched_hosts': matched,
                      'inventory_generated_utc': snapshot.generated_utc if snapshot is not None else None}
        if upstream_identity is not None:
            provenance['mtat_upstream'] = upstream_identity
        write('assessment_manifest.json', json.dumps(provenance, indent=2).encode('utf-8'))
        if hardware:
            fleet, summary, archive, reports = _regenerate_fleet_artifacts(results, failed, outdir, save_json=True, vinv_snapshot=snapshot, mtat_html=panel)
            if results and (not fleet or not summary or not archive):
                raise OSError('Combined artifact generation incomplete')
            with _state_lock:
                _state.update(fleet_path=fleet, summary_path=summary, zip_path=archive, report_paths=reports)
        else:
            from vcf_hci.logging_utils import create_scan_zip_archive
            create_scan_zip_archive(outdir)
        handler._send_json({'ok': True, 'outdir': outdir, 'files': written, 'inventory_matched_hosts': matched, 'bmc_hosts': len(results)})
    except Exception:
        import logging
        logging.getLogger(__name__).exception('Wizard artifact finalization failed')
        handler._send_json({'error': 'Could not save combined artifacts. See server log; completed jobs remain available in Plugins.'}, 500)
    finally:
        with _state_lock:
            _state['_fleet_worker_active'] = False
