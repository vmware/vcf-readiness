"""XML/HTML-escape helper used by fleet report generators."""
from vcf_hci.report.helpers import _h


def _xe(s) -> str:
    """XML/HTML-escape helper that safely escapes quotes."""
    return _h(s)
