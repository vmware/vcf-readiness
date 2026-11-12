"""Remove structured identifiers wherever they are repeated in report evidence."""
import re
from typing import Any, Callable, Dict

_MAC = re.compile(r'(?<![0-9a-f:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:])', re.I)
_EMBEDDED_SERIAL = re.compile(r'\bserial[-_:]([a-z0-9][a-z0-9-]{5,})', re.I)
_EMPTY = {'unknown', 'none', 'n/a', 'not available', 'not specified', 'not present', 'not installed',
          'default string', 'to be filled by o.e.m.', 'no dimm', 'not applicable', 'redacted', '[redacted]'}
_PUBLIC_DOMAINS = {'vmware.com', 'broadcom.com', 'dell.com', 'hpe.com', 'cisco.com', 'lenovo.com'}
_DEFAULT_ACCOUNTS = {'root', 'admin', 'administrator', 'userid', 'operator', 'guest', 'support'}
_GENERIC_ACCOUNT_WORDS = _DEFAULT_ACCOUNTS | {'vmware', 'username', 'user', 'test', 'monitor', 'readonly', 'read-only', 'service', 'backup', 'scan', 'login', 'password', 'dell'}
_LOGIN_ACCOUNT = re.compile(r'\blog(?:ged)?\s*in\s+(?:for|as)\s+([a-z0-9_.@\\-]+)', re.I)


def scrub_identity_references(source: Any, target: Any, tokenize: Callable[[str, str], str]) -> Any:
    """Scrub identifiers in free text, resource keys and nested vendor records.

    Discover identifiers before obfuscation so their copies in component names,
    firmware IDs and certificate subjects are replaced along with the typed field.
    Hardware models, part numbers and firmware versions are not identifiers here.
    """
    replacements: Dict[str, str] = {}

    def add(kind: str, value: str) -> None:
        value = value.strip()
        if len(value) < (3 if kind == 'account' else 6) or value.lower() in _EMPTY or len(set(value.replace(':', '').replace('-', ''))) < 3:
            return
        if kind == 'domain' and value.lower() in _PUBLIC_DOMAINS:
            return
        replacements.setdefault(value.lower(), tokenize(kind, value))

    def discover(value: Any, field: str = '') -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                discover(child, str(key))
        elif isinstance(value, list):
            for child in value:
                discover(child, field)
        elif isinstance(value, str):
            key = re.sub(r'[^a-z0-9]', '', field.lower())
            if key.endswith(('serialnumber', 'serial', 'servicetag', 'chassisserial', 'encloseserialnum')):
                add('serial', value)
            elif key.endswith('assettag'):
                add('asset', value)
            elif key.endswith(('hostname', 'dnsname', 'dnsracname', 'fqdn')):
                add('hostname', value)
            elif key.endswith(('dnsdomainname', 'domainname')):
                add('domain', value)
            elif key.endswith(('username', 'loginname', 'emailaddress')) and value.lower() not in _GENERIC_ACCOUNT_WORDS:
                add('account', value)
            elif key.endswith(('uuid', 'nguid')):
                add('uuid', value)
            elif key.endswith(('macaddress', 'mac', 'associatednetworkaddresses')):
                if re.fullmatch(r'[0-9a-f]{12}', value, re.I):
                    add('mac', value)
            elif key.endswith(('wwn', 'wwpn', 'wwnn', 'sasaddress', 'durablename', 'eui64')):
                if re.fullmatch(r'[0-9a-f:-]{8,}', value, re.I):
                    add('storage_id', value)
            for match in _MAC.finditer(value):
                add('mac', match[0])
            for match in _EMBEDDED_SERIAL.finditer(value):
                add('serial', match[1])

    discover(source)

    def discover_accounts(value: Any, field: str = '') -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                discover_accounts(child, str(key))
        elif isinstance(value, list):
            for child in value:
                discover_accounts(child, field)
        elif isinstance(value, str):
            normalized = re.sub(r'[^a-z0-9]', '', field.lower())
            if (normalized.endswith(('username', 'loginname', 'emailaddress'))
                    and value.lower() not in _GENERIC_ACCOUNT_WORDS
                    and not re.fullmatch(r'(?:USER|ACCOUNT|HOST)-[0-9a-f]+', value, re.I)):
                add('account', value)
            for match in _LOGIN_ACCOUNT.finditer(value):
                account = match[1].rstrip('.')
                if account.lower() not in _GENERIC_ACCOUNT_WORDS:
                    add('account', account)

    discover_accounts(target)
    pattern = re.compile(r'(?<![a-z0-9])(?:' + '|'.join(re.escape(v) for v in sorted(replacements, key=len, reverse=True)) + r')(?![a-z0-9])', re.I) if replacements else None

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                normalized = re.sub(r'[^a-z0-9]', '', str(key).lower())
                if (normalized.endswith(('username', 'loginname', 'emailaddress'))
                        and isinstance(child, str) and child.strip()
                        and child.lower() not in _DEFAULT_ACCOUNTS | _EMPTY
                        and not re.fullmatch(r'(?:USER|ACCOUNT|HOST)-[0-9a-f]+', child, re.I)):
                    child = tokenize('account', child)
                if normalized.endswith(('password', 'chapsecret', 'clientsecret', 'accesstoken', 'authtoken', 'authorization')) and isinstance(child, str) and child.strip():
                    child = '[REDACTED]'
                result[scrub(key) if isinstance(key, str) else key] = scrub(child)
            return result
        if isinstance(value, list):
            return [scrub(child) for child in value]
        if isinstance(value, str):
            if re.search(r'-----BEGIN [A-Z0-9 ]+-----', value):
                return '[REDACTED CERTIFICATE/KEY]'
            return pattern.sub(lambda m: replacements[m[0].lower()], value) if pattern is not None else value
        return value

    return scrub(target)
