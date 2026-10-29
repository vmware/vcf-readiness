"""Anonymous, bounded vCenter identification and installed VDT selection.

Discovery never authenticates or executes an installed payload. Version selection
establishes documented release compatibility; managed execution additionally needs
an audited adapter and a successful appliance runtime preflight.
"""

import http.client
import ipaddress
import re
import ssl
import xml.etree.ElementTree as ET
from typing import Optional, Tuple

from vcf_hci.tls_utils import MetadataPinnedHTTPSConnection

MAX_DISCOVERY_BYTES = 256 * 1024
DISCOVERY_TIMEOUT = 15
_SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
_VIM_NS = 'urn:vim25'
_REQUEST = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    b'xmlns:vim="urn:vim25"><soapenv:Body><vim:RetrieveServiceContent>'
    b'<vim:_this type="ServiceInstance">ServiceInstance</vim:_this>'
    b'</vim:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'
)


def _version_tuple(value: object) -> Optional[Tuple[int, ...]]:
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(r'\d+(?:\.\d+){1,5}', value):
        return None
    return tuple(int(part) for part in value.split('.'))


def _host(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('Enter a vCenter hostname or IP address.')
    clean = value.strip()
    if clean.startswith('[') and clean.endswith(']'):
        clean = clean[1:-1]
    if not clean or len(clean) > 253 or any(ord(char) < 33 or ord(char) == 127 for char in clean):
        raise ValueError('Enter a vCenter hostname or IP address.')
    try:
        ipaddress.ip_address(clean)
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', clean):
            raise ValueError('Enter a vCenter hostname or IP address, without a URL or credentials.') from None
    return clean


def _parse_about(raw: bytes) -> dict:
    if len(raw) > MAX_DISCOVERY_BYTES:
        raise ValueError('The vCenter discovery response exceeds 256 KiB.')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        raise ValueError('The vCenter returned an unsupported discovery response encoding.') from None
    # Reject DTDs and entities before ElementTree can expand them. Reject NULs so
    # an XML parser cannot reinterpret nominally UTF-8 input as UTF-16/32.
    if '\x00' in text or re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.IGNORECASE):
        raise ValueError('The vCenter returned an unsafe XML discovery response.')
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        raise ValueError('The target did not return valid vCenter discovery XML.') from None
    if root.tag != '{' + _SOAP_NS + '}Envelope':
        raise ValueError('The target did not return a vSphere SOAP discovery response.')
    body = root.find('{' + _SOAP_NS + '}Body')
    response = body.find('{' + _VIM_NS + '}RetrieveServiceContentResponse') if body is not None else None
    if response is None:
        raise ValueError('The target did not return vCenter service information.')
    about = response.find('{' + _VIM_NS + '}returnval/{' + _VIM_NS + '}about')
    if about is None:
        raise ValueError('The target did not return vCenter product information.')
    fields = {}
    for field in ('version', 'build', 'apiType', 'name'):
        node = about.find('{' + _VIM_NS + '}' + field)
        value = (node.text or '').strip() if node is not None else ''
        if len(value) > 200 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('The target returned invalid vCenter product information.')
        fields[field] = value
    if fields['apiType'] != 'VirtualCenter':
        raise ValueError('This endpoint is not a vCenter Server. Select its managing vCenter instead.')
    if _version_tuple(fields['version']) is None:
        raise ValueError('The target returned an unrecognized vCenter version.')
    return {'version': fields['version'], 'build': fields['build'],
            'api_type': fields['apiType'], 'name': fields['name']}


def probe_vcenter(host: str, port: int = 443) -> dict:
    """Read anonymous ServiceContent through HTTPS, with no credentials or redirects.

    The reused HTTPS connection resolves through the existing metadata-address
    guard and dials checked addresses directly, retaining the original SNI/Host.
    Appliance self-signed certificates are accepted; this probe is not identity
    attestation and the caller must still verify the SSH fingerprint separately.
    """
    clean = _host(host)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError('Enter a vCenter HTTPS port from 1 through 65535.')
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = MetadataPinnedHTTPSConnection(clean, port=port, timeout=DISCOVERY_TIMEOUT, context=context)
    try:
        connection.request('POST', '/sdk', body=_REQUEST, headers={
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept': 'text/xml, application/xml',
            'Accept-Encoding': 'identity',
            'SOAPAction': '"urn:vim25/6.0"',
            'Connection': 'close',
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Could not identify vCenter through its anonymous HTTPS SDK endpoint. '
                             'Check the hostname, network access and HTTPS port.')
        length = response.getheader('Content-Length')
        if length is not None:
            try:
                size = int(length)
            except ValueError:
                raise ValueError('The vCenter returned an invalid discovery response length.') from None
            if size < 0 or size > MAX_DISCOVERY_BYTES:
                raise ValueError('The vCenter discovery response exceeds 256 KiB.')
        if (response.getheader('Content-Encoding') or 'identity').lower() != 'identity':
            raise ValueError('The vCenter returned an unsupported compressed discovery response.')
        result = _parse_about(response.read(MAX_DISCOVERY_BYTES + 1))
    except (OSError, http.client.HTTPException):
        raise ValueError('Could not reach the vCenter HTTPS SDK endpoint. Check the hostname, network access and HTTPS port.') from None
    finally:
        connection.close()
    return {'host': clean, 'port': port, **result,
            'source': 'anonymous-vsphere-sdk', 'tls_verified': False}


def select_vdt(installations: list, detected_version: str) -> dict:
    """Choose a documented compatible installation without granting execution.

    6.5/6.7 use 1.1.4. 7.x prefers 2.2.3+; 1.1.4 is an explicitly manual-only
    alternative. 8.x/9.x use 2.2.3+. Unknown future product releases fail closed.
    Only exact VDT 2.3.2 has an existing audited managed adapter. Its appliance
    Python/runtime requirements remain a separate preflight, including on 7.x.
    """
    parsed = _version_tuple(detected_version)
    result = {'vcenter_version': detected_version if isinstance(detected_version, str) else '',
              'compatible': False, 'selected_folder': '', 'selected_version': '',
              'selected_family': '', 'remote_supported': False,
              'requires_preflight': True, 'candidates': [], 'reason': ''}
    if parsed is None or not (parsed[0] in (7, 8, 9) or parsed[:2] in ((6, 5), (6, 7))):
        result['reason'] = 'No documented VDT compatibility is configured for this vCenter release. Do not run a payload automatically.'
        return result
    candidates: list[dict] = []
    for item in installations:
        if not isinstance(item, dict):
            continue
        products = item.get('products')
        if not isinstance(products, list) or 'vcenter' not in products:
            continue
        versions = item.get('versions')
        version = versions.get('vcenter') if isinstance(versions, dict) else None
        tool_version = _version_tuple(version)
        folder = item.get('folder')
        if tool_version is None or not isinstance(folder, str) or not folder:
            continue
        legacy = version == '1.1.4'
        modern = tool_version[0] == 2 and tool_version >= (2, 2, 3)
        compatible = legacy if parsed[0] == 6 else modern or (parsed[0] == 7 and legacy)
        if compatible:
            candidates.append({'folder': folder, 'version': version, 'family': '1' if legacy else '2',
                               'remote_supported': version == '2.3.2'})
    candidates.sort(key=lambda item: (tuple(-part for part in (_version_tuple(item['version']) or ())), item['folder'].casefold()))
    result['candidates'] = candidates
    if not candidates:
        wanted = 'VDT 1.1.4' if parsed[0] == 6 else 'VDT 2.2.3 or later in the 2.x branch'
        result['reason'] = 'Install ' + wanted + ' for this vCenter release.'
        return result
    selected = candidates[0]
    result.update(compatible=True, selected_folder=selected['folder'], selected_version=selected['version'],
                  selected_family=selected['family'], remote_supported=selected['remote_supported'])
    if selected['family'] == '1':
        result['reason'] = ('VDT 1.1.4 is compatible with this vCenter release, but legacy execution is manual only. '
                            'The managed adapter does not support the legacy appliance runtime or export format.')
    elif selected['remote_supported']:
        result['reason'] = ('VDT 2.3.2 has a reviewed managed adapter. Complete appliance preflight before running: '
                            'Python 3.9 or newer and the reviewed native runtime are required; version selection alone does not establish runtime support.')
    else:
        result['reason'] = ('This VDT release is documented as compatible, but has no reviewed managed adapter. '
                            'Use manual collection or install the reviewed VDT 2.3.2 payload.')
    return result
