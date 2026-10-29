"""Emit the standalone, release-pinned VDT appliance adapter (stdlib only).

The generated source executes only on an explicitly selected appliance in a
private transport sandbox. It is never imported into the local web process.

Payload SHA-256 values pin the statically reviewed VDT 2.3.2 distribution.
Updating them requires reviewing native entry points, imports and check scope.
"""

_RUNNER_SOURCE = r'''"""Standalone appliance-side VDT adapter; emitted by appliance_runner_source()."""
import builtins
import configparser
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
from urllib.parse import quote, urlparse, parse_qs

# Replaced with exact audited release hashes when this source is packaged.
APPROVED_FILES = {'CHANGELOG': 'ec260fed283c909702c6215adc69e195fb63f2e5ae74fa04dced2af0c633adf3',
 'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
 'README.md': '4b0a26a321d7308f14309fa88373c60edef5230ccda897117bb1d949e492bb0f',
 '__init__.py': '160ff646e3a55c668b9ebf7f8bc27969601c881e49fa4fe82e4f52e3860461dc',
 'cfg/__init__.py': '448a72dd9d92f7e9aa716188586e7c06d2ef20221511fe87adc7837edc56c999',
 'cfg/vdt.ini': '8c9b1b53c5d823582c2730b35289026752afc67e3c2bf580e18720c4069b7fd6',
 'cfg/vdt_defaults.py': 'd8abd15617c90f2d856a8bb244ab84d36b52fd6660b23c4576d48f5312ea6a2c',
 'example/ex_cfg/example.ini': '46154c9a02cbba3aefe8fd94941e648276425a2f85085b2520b31294975b8052',
 'example/ex_scripts/ex_example.py': '180fcd18f2201e92755a05c92a83f550f33b30addb7cd69408a3cbc12ac3db25',
 'example/example.py': 'a242fad013c6da56c7e82b553dcbe1ecd397b102fc568b39469cf3f97f727de7',
 'lib/__init__.py': '2dadd34b5c5508b3824d22dad5088f443dfcacc391c63384621e1feaa2ada7ca',
 'lib/vdt_base.py': 'f4d9b5229f5954d59b285d4e19e090fe20f036dc953715c9c1541606921ee2b0',
 'lib/vdt_formatter.py': 'a2dfe47026162a73de123d09dcd8ccaaadc3a728e23df885b5fb74b83a1f868c',
 'sddc_manager/CHANGELOG': 'acba6bde9d11b4fb7fc89d9d7020228eb479d16b5b72646915e228587346fe8e',
 'sddc_manager/__init__.py': 'a4dc297424be71c2f50b174b8ad27012a2eb8984c06befb1c19c35a608902471',
 'sddc_manager/sddc_cfg/__init__.py': '256b1a3968c74ce0e6ccffd45ccfcd8dd752517ffc475882b77091a6ea90593e',
 'sddc_manager/sddc_cfg/current_defaults.py': 'ab30e07d9e923092f39d59a4c1ca8488d0c369132aa201449ce314ca4355eebf',
 'sddc_manager/sddc_cfg/defaults.ini': '995e908d58da2eaf3aa66189e351153e07e534b8c27d9d20668713206544325e',
 'sddc_manager/sddc_cfg/sddc_defaults.py': '70b031a64a1f294109c84070e21397c0442caef8e704bc4fd1783c14fe684fa6',
 'sddc_manager/sddc_cfg/sddc_vdt.ini': '3747f023075fdf9f66f850e924f22e3613e85f90bd6f9da7a0d6986d2ddecc0c',
 'sddc_manager/sddc_lib/__init__.py': '77770ad8bb50773431e6e594ff190dfa8ebf72f2e5adbf36278ef7eafd0597b9',
 'sddc_manager/sddc_lib/authUtils.py': '4b2acd96da525a65b413089433243f8019aba4ab2223d3e0c5e80c36fef9621d',
 'sddc_manager/sddc_lib/certUtils.py': 'ec6f32100b8cbefb83cda60069f5433a7c19a320d4f71d5790034cb5bb261480',
 'sddc_manager/sddc_lib/commandUtils.py': 'b36e816be671ee43bce9cb2bf1c2be8acdd39e85951c019bc03240b3dc95a351',
 'sddc_manager/sddc_lib/inventoryUtils.py': '47e1a03b029e3608fdda875b79ce8c9e4a6b740fb82ee35559a775cba96e5698',
 'sddc_manager/sddc_scripts/CertCheck_nsx.py': '717128667181ae334ab3c80bf098a7eadd03c3cf8885e722006285ef75a34850',
 'sddc_manager/sddc_scripts/CertCheck_sddc.py': 'f53914a7edcb88eb8391b6e9bfe4752b75fd27070bbd49a23afd9c377ebf7fe5',
 'sddc_manager/sddc_scripts/CertCheck_vc.py': '1d00bc00d98fee5fc5a5c5e9452f95d538864928f9512101c3d5afc007524b76',
 'sddc_manager/sddc_scripts/__init__.py': '6afc54c9fb839462895a3c9a08fa2d8c0a6b2831d6bbb97b61135336395ac8fd',
 'sddc_manager/sddc_scripts/aria-suite_info.py': '0099d73d8ead17baf1750ce0d8ec217e26c96d546d8cc4b4b54ebdb7f71276ee',
 'sddc_manager/sddc_scripts/checkManifest.py': '9f8b195ad1c303d56ee496c75c0398da4caacf283511c37bef265a0dce05920f',
 'sddc_manager/sddc_scripts/checkPantheonBundle.py': '7d652cbc1729a5c78de44f1983d4d148a8b895cc3b5a49ec9a15325db221b76c',
 'sddc_manager/sddc_scripts/check_commonsvcs.py': '76111a7a8195d8682c1fd4ebd93a650bfc029f9a450dfcd9e8534ef39641e38a',
 'sddc_manager/sddc_scripts/check_cred.py': 'e7aff8306732375067ffa80aced6980e41e2b48e997d29ae869f4877ecf33f9b',
 'sddc_manager/sddc_scripts/check_status.py': 'dc2c6bb5756b401840e57b1f57b835df499adc425bb9db9dc40e42093bc06383',
 'sddc_manager/sddc_scripts/credential_history.py': 'bb9744d91c404c9ee20556aee3ccbc6994dfe4b8dcc975ea5946190144dbbc26',
 'sddc_manager/sddc_scripts/dbchangeloglock.py': 'ee0c0f5e58994e4d55c55c183572196ef61e2a297a8ba60f7b0238ebce28779d',
 'sddc_manager/sddc_scripts/feature_properties.py': 'b129369adeb4ee496dd9bfdaf2719ca1bd4a3f9e4a09525753d461a44d12fbfe',
 'sddc_manager/sddc_scripts/lcmChecks.py': '7b110e5ed7484c2bcadcb241c363ddfdfac34df479152d2beab8481c98b94948',
 'sddc_manager/sddc_scripts/lcmCrash_bundleCheck.py': '61118add85220a6e30fcd90b4efaba9716bda55c8db10f84d85bf38bab430d3e',
 'sddc_manager/sddc_scripts/lockCheck.py': 'a3222a68ba7372a17cce769f7be9ffc095aa49e0aac7dec84b84995026a8759f',
 'sddc_manager/sddc_scripts/nsxChecks.py': '0380323cd3352e465d39044fced0e6037d2fe544cce578c4876aa02740587a3f',
 'sddc_manager/sddc_scripts/sddc-m_info.py': '655f0c28643abf1e2ece732715e0f83dc6ca094b9df1f5ddddc6aaca63ef2252',
 'sddc_manager/sddc_scripts/sddc-m_services.py': '381037be58f9aa2185987b68e6d3ee7fa64cf171a61f49223a77800aea38759c',
 'sddc_manager/sddc_scripts/sddc_check_disk_space.py': '58caa44deaf6d6c2a67f62d0b96acef5b32d7ff6029e76e27db75f15e56cac8c',
 'sddc_manager/sddc_scripts/sddc_depot_check.py': '7f05679ed779776a93f5748a9e82cc353959f1117328265f12a417610144967c',
 'sddc_manager/sddc_scripts/sddc_file_ownership_check.py': '3680c55bd474a37b9064f40a292f3116ee75df544953d5452c3484717528ff85',
 'sddc_manager/sddc_scripts/sddc_hosts_file_check.py': '30e162ba4a575923dd44e94d1af548d5e5b75f8354a54a16dd7a8acf9f988a2e',
 'sddc_manager/sddc_scripts/sddc_nfs-mount_perm_own_check.py': 'a50770ad6b015c9dfb81928b75281777e8e1fd79185882319890e6f4e78a2e24',
 'sddc_manager/sddc_scripts/sddc_ntp_check.py': '603f4ce8c2938d7438caf7cd671e07a111ddc2e43627ec21b98b4a5b5754c296',
 'sddc_manager/sddc_scripts/sddc_vc_root_check.py': '22a79ad36f90e3234fb07fd811c4fcb111ba31b768b3fc534a5ea9370ab42a83',
 'sddc_manager/sddc_scripts/serviceAcctCheck.py': 'c291433578719be9e9443a82a047ff46a06384e616ea476250604e625649e9b8',
 'sddc_manager/sddc_scripts/stale_cred_check.py': '8f1d5661d1a5d6fdd510be6f3e95eee1f0eb5438a20fb2c3f5064c7356e20187',
 'sddc_manager/sddc_scripts/syslog.py': '51a105672224383153a2321594d39ca24fda482399dc9245755b14e5fb480f5e',
 'sddc_manager/sddc_vdt.py': 'ce3f0f9597fe1d7884d071869d47ee410775be95f29bc08f1790e136f0b9329c',
 'vcenter/CHANGELOG': 'c3f338e6b9ba12b9817105c268f102ee299cb5fcf1c580ca249d47bef25e5baf',
 'vcenter/__init__.py': '5f945bcaebc83c1abf29ecdb02dcb0d31f78ed0affb5eb40ba0b25c4f6789d80',
 'vcenter/vc_cfg/__init__.py': 'c153c1e9198e2d671c3a3becb4d26b67be3976b5c33e092239a8111dd5090d79',
 'vcenter/vc_cfg/current_defaults.py': 'ae0cbbc1fd2497790d2eaf970e2773327067c338820911bcc3d4c5a1ff75baa8',
 'vcenter/vc_cfg/defaults.ini': '6c76c8a9f1cda0ce244533cd4f58ad82e5162784da8915544713fd4a0389f0d3',
 'vcenter/vc_cfg/vc_defaults.py': '790f90e014aa43ab3a967e00fba1c88f0315999fe6f062e5189c3500b04e440f',
 'vcenter/vc_cfg/vc_vdt.ini': '0d58cd39a5ed0910dbd01f7a39b5b89defeb4964a63d1c3b9e62c17d01827f9d',
 'vcenter/vc_lib/__init__.py': '97f0891cf300ef2367306aa2fed66db75535de230ad8dff0c1db3c20bf7813eb',
 'vcenter/vc_lib/cert_utils.py': '0e6e33840262e7996e075577c376a8b5cfbd39fdf8278e03de06cb27d55f6bfa',
 'vcenter/vc_lib/common.py': '43716c656dc5a27191853e9ab3c0f5ea2eccb3c2cebadce36eccc06d37043b7e',
 'vcenter/vc_lib/ls_utils.py': 'ff7ebeea3f91e0a516879a7af7bac8c186c261a467de9029ce0a4baeb882bd7a',
 'vcenter/vc_lib/lstool_parse.py': 'bf858cbd043fef206b7907336fbd1f8564984c8ed82100eab6b6f0062c60c480',
 'vcenter/vc_lib/lstool_scan.py': 'eb1fa4df01857b3d43c68fec66e81b7985659e054e4546e53b307295810d7497',
 'vcenter/vc_scripts/__init__.py': '2718db9e48ea92dc72cbea46db1211b95c8fbc7f5513bf3088d32a783c30e0ec',
 'vcenter/vc_scripts/lsreport.py': 'eb9e0f9b6450f846c8699b7e823fc89640ac2d4d17c6d2ee5c5ba151062e33f2',
 'vcenter/vc_scripts/pnid_check.py': '70aaeae5033211ee5f358589fcc7706c217aa21f8930991306ba0f68dd5c794d',
 'vcenter/vc_scripts/soluser_map.json': '8321e2690bb3f9e0fc46868927221034998c7010667b7e5cd7419f11a0473ee7',
 'vcenter/vc_scripts/vc_ad_check.py': 'e1b40a912fed704a48bdb7021d85f95ed5c6c089398cac0cbcd0fbb8b53c6208',
 'vcenter/vc_scripts/vc_cert_check.py': '2121955c77adc8a305308a9dcf8849b82527b47e868c27b936466a397f90e2a4',
 'vcenter/vc_scripts/vc_cluster_check.py': 'e76499058b755f73192ce65bfaa99c2c3be23ea02e6ff10ce20d7f01bca7a211',
 'vcenter/vc_scripts/vc_corefile_check.py': '9bec4016bc54e67004b8ff34a36b5099bc85623e05e2489005c67c995b624fe8',
 'vcenter/vc_scripts/vc_db_check.py': '21cb7fef868257cc6edc2f2b0a32f2b6a1cb2bb0e2f143e3cdcf3fddadb3daea',
 'vcenter/vc_scripts/vc_disk_space.py': 'f837c19c9c81a08a7ffe31bd479e599e4705615c9079167a2b7197fe42a3838d',
 'vcenter/vc_scripts/vc_dns.py': '48d03aa5c8296b568f50f82a477eea9a53f2c472440a62f39cbd77eb9326fb20',
 'vcenter/vc_scripts/vc_identitysource_check.py': '4de7435f7ef1b8195d399f1ad1ae857c13b5e355fef0dddf58aae11a378ad8c0',
 'vcenter/vc_scripts/vc_info.py': 'e590cf02e4fdcbf8029e13f463d23d4aacc849fdc9b41b07b992406caa55ace8',
 'vcenter/vc_scripts/vc_ntp.py': '80a0dd1bcdd8ec98c0a31a3108a2a38372f25f90c0e0c7e30dcada1b29f571f9',
 'vcenter/vc_scripts/vc_root_check.py': '8d489d1171bd8dbdcce390d41c672fdf727066148faf0853163251356862489a',
 'vcenter/vc_scripts/vc_services.py': 'dc2ccadaf237191eb5eaf15659266aa05ba91d23d92d1521cc585ee0f7570f28',
 'vcenter/vc_scripts/vc_soluser_checks.py': 'aff12e758158420454da278bb58f753f25af61a382b758b87e8b14a0dac2e7f9',
 'vcenter/vc_scripts/vc_syslog_check.py': 'dede04483006aff2879000a32cbb3ea93694ef0b6423e6d31e699dd36def4fe4',
 'vcenter/vc_scripts/vc_update_check.py': '655a98bef9d7b49742f5f65917da387524cdaea928031e00ae222594d326f630',
 'vcenter/vc_scripts/vc_vcha_check.py': '2e18ef9767f4aa868d5c62fea4fbfc8772fccc0bf84571618e2585c24e5d404a',
 'vcenter/vc_scripts/vc_vmdir_check.py': '7bbd936e5e072ca46619f162b885da46f6d5e0b8190b79a61124ec06ab1b4fab',
 'vcenter/vc_scripts/vc_vum_schema_check.py': '6126119f9241c7fb2511d0aac68b4df1fa2f9f91dc4ee5a57ac2cd203e68cf1a',
 'vcenter/vc_vdt.py': '3f22f21ba068e0a3d517a9e11b535bdeb0d0fe87e42ee7abc728bd2ba96124eb',
 'vdt.py': 'a2031efb6500fe012769dcee0ad04da499ffc13f40dd3bfda81af660d65741c9',
 'vks/CHANGELOG': '68babe78eaa72bbf09cbca1ff3bb9bb9e38f25b9cc422f4df92c761d627b5577',
 'vks/__init__.py': 'e7fb637c7700fcb654225a1e63b718e57afa2c8e65d1109d8152f17ec1df00f8',
 'vks/vks_cfg/__init__.py': '3e45af375c55c423eb66982d947aa2118fec191aa9cb8f25121d0cbdf3d57da9',
 'vks/vks_cfg/current_defaults.py': '13814e417a922706b48e1756df065367717ed00b0d51a199c4cc03bd989a0211',
 'vks/vks_cfg/defaults.ini': '995e908d58da2eaf3aa66189e351153e07e534b8c27d9d20668713206544325e',
 'vks/vks_cfg/vks_defaults.py': 'dc20d8af97c9ce232c611751b37f6e36023f602320eaf154d1716105baabd02e',
 'vks/vks_cfg/vks_vdt.ini': '0f28b04a3c013d6bff747d5e4d3de0c538cfd459e8b7d940c23e89f1369bc814',
 'vks/vks_lib/__init__.py': '778206d0ec545e3d877df7a9cd07188b11e565ebaeb8330015ad3d1ffe8bb665',
 'vks/vks_lib/common.py': 'f6255ddfb2fee920ea744f50780a59349123d1df806095b77bc8c70cef0ec031',
 'vks/vks_lib/vks_db_utils.py': 'c94e608bce33f570b1f23dea1febfa2347d4d7d05371c27e5f55a0c8d20af13b',
 'vks/vks_lib/vks_supervisor_manager.py': 'b7c31d7e90a156adfcb8f7809b8703043b2dfbd4e97526aa4e4aa1a93b9d55b1',
 'vks/vks_lib/vks_sv_utils.py': 'a12c0c96dfacdb879191c5c8575eedba30c32c7507b545db7abd4e66487067de',
 'vks/vks_lib/vks_tkc_utils.py': '93e802361e027157748636428186c1a3d9e6f2d8d20c91679a6825ed7c54849e',
 'vks/vks_scripts/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'vks/vks_scripts/vks_cns_checks.py': 'fc5e335f5f803da8d075512d7ad4ee08100b8dc11fcf55da3595d75998dcfc1c',
 'vks/vks_scripts/vks_info.py': '92bd31926a2c69fd9806e22691635732002198d8ce41624840595f39a75a1b63',
 'vks/vks_scripts/vks_sv_checks.py': '93e0499011b057d2f4b39b2cd1ead1c93e5fdd0b1d2dad6bb8c6cb2e9df33579',
 'vks/vks_scripts/vks_sv_cluster_checks.py': '6679ff88badfeba12071b1ba22e3d597feac1ba5723327af1149b2e0275970d0',
 'vks/vks_scripts/vks_sv_etcd_checks.py': 'ed202820382106f8dc1948ba810b95b0fe0e0af0b4fbe00782c54a786721c14a',
 'vks/vks_scripts/vks_sv_object_checks.py': 'e980c22a4f7b6387a470e8f9c3930bf379b69068511bed2507aab97d3193e4f2',
 'vks/vks_scripts/vks_tkc_checks.py': 'd520d1e81f7a78a19b9b48e2022ab27d515a333969a56883141c17a07f75bc3a',
 'vks/vks_scripts/vks_tkc_resource_checks.py': 'abca66593b3f1114570c2f3b61e9b817580d8315e7ad46a3d78839f6b68a76cd',
 'vks/vks_scripts/vks_tkc_system_checks.py': '19e591ff22c363b53c9992f778c4ba45bded7bd9177431d8e2e60b916d1e5ff9',
 'vks/vks_scripts/vks_vc_info.py': '4a8716529fc5cea95df050f549cc69d67fa2a82d9a8f786c05805821da761a2d',
 'vks/vks_scripts/vks_wcp_checks.py': '32bf2725186da9dc643df6fbdd2940a7f52466635b7a81c875514d88dd3a274a',
 'vks/vks_vdt.py': '4d5a1cf8d6b2585ec105eae534f777d1cdeecd9864ccb86e81df796fb73a5050'}
ADAPTER = "vcfr-vdt-vcenter-bounded-1"
MAX_INPUT = 65536
MAX_ARTIFACT = 16 * 1024 * 1024
TIMEOUT = 900
CHECKS = (
    "vc_info", "vc_inv_summary", "proxy_check", "root_check", "service_check",
    "service_priority_check", "diskspace_check", "inode_check", "storage_log_check",
    "vmafd_log_check", "corefile_check", "hprof_check", "vc_cluster_ssloptions_check",
)


class RunnerError(Exception):
    code = "collection_failed"
    message = "VDT collection failed. Check appliance prerequisites and supported release."


class CredentialsRequired(BaseException):
    code = "credentials_required"
    message = "Supply valid vCenter SSO credentials. Authentication was not retried."


class UnsupportedProduct(RunnerError):
    code = "unsupported_product"
    message = "Automatic collection currently supports vCenter only. Import VKS or SDDC Manager JSON manually."


class SourceMismatch(RunnerError):
    code = "source_mismatch"
    message = "VDT payload differs from the audited 2.3.2 release. Restore the approved original payload."


class BoundaryViolation(RunnerError):
    code = "boundary_violation"
    message = "VDT requested an operation outside the bounded collection policy."


class UnexpectedPrompt(BaseException):
    code = "unexpected_prompt"
    message = "VDT requested an unsupported interactive response. Collection stopped."


def secret_payload(raw):
    try:
        if len(raw) > MAX_INPUT:
            raise ValueError()
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) - {"product", "sso_username", "sso_password"}:
            raise ValueError()
        if not isinstance(data.get("product"), str):
            raise ValueError()
    except (ValueError, TypeError, UnicodeError):
        error = RunnerError()
        error.code = "invalid_input"
        error.message = "Expected one JSON object containing product and optional SSO credentials."
        raise error from None
    if data["product"] != "vcenter":
        raise UnsupportedProduct()
    for key in ("sso_username", "sso_password"):
        if not isinstance(data.get(key), str) or not data[key] or len(data[key]) > 8192 or "\x00" in data[key]:
            raise CredentialsRequired()
    return data


def sandbox_root(path):
    root = Path(path).resolve()
    if root.parent != Path("/tmp").resolve() or not re.fullmatch(r"vcfr_vdt_[0-9a-f]{32}", root.name):
        raise BoundaryViolation()
    if Path(path).is_symlink():
        raise BoundaryViolation()
    # Transport owns marker lifecycle. Runner independently enforces the exact path pattern.
    return root


def verify_payload(payload):
    if not payload.is_dir() or payload.is_symlink():
        raise SourceMismatch()
    observed = {}
    for path in payload.rglob("*"):
        if path.is_symlink():
            raise SourceMismatch()
        if path.is_file():
            if "__pycache__" in path.parts or path.suffix == ".pyc" or path.name in (".DS_Store", "Icon\r"):
                continue
            if path.stat().st_size > MAX_ARTIFACT:
                raise SourceMismatch()
            observed[path.relative_to(payload).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != APPROVED_FILES:
        raise SourceMismatch()
    config = configparser.ConfigParser(interpolation=None)
    config.read(str(payload / "vcenter/vc_cfg/vc_vdt.ini"))
    if config.get("vdt", "version", fallback="") != "2.3.2":
        raise SourceMismatch()


def prepare_copy(root):
    original = root / "payload"
    verify_payload(original)
    work = root / "runtime"
    artifacts = root / "artifacts"
    if work.exists() or artifacts.exists():
        raise BoundaryViolation()
    shutil.copytree(str(original), str(work), ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", "Icon\r"))
    os.chmod(str(work), 0o700)
    artifacts.mkdir(mode=0o700)
    for config_path in work.rglob("*.ini"):
        config = configparser.ConfigParser(interpolation=None)
        config.read(str(config_path))
        if config.has_section("logging"):
            config.set("logging", "logdir", str(artifacts))
            config.set("logging", "level", "CRITICAL")
        if config.has_section("paths"):
            if config_path == work / "cfg/vdt.ini":
                config.set("paths", "root_path", str(work))
            elif config_path.name.endswith("vdt.ini"):
                config.set("paths", "root_path", str(config_path.parent.parent))
        with config_path.open("w") as handle:
            config.write(handle)
    selected_config = work / "vcenter/vc_cfg/vc_vdt.ini"
    config = configparser.ConfigParser(interpolation=None)
    config.read(str(selected_config))
    excluded = []
    for section in list(config.sections()):
        if section.startswith("check:") and section[6:] not in CHECKS:
            excluded.append(section[6:])
            config.remove_section(section)
    with selected_config.open("w") as handle:
        config.write(handle)
    # Keep all upstream source and copyright/permission notices untouched.
    return work, artifacts, excluded


def is_within(path, root):
    try:
        Path(os.fsdecode(path)).resolve().relative_to(root)
        return True
    except (ValueError, TypeError, OSError):
        return False


def command_allowed(argv):
    if not isinstance(argv, (list, tuple)) or not argv:
        return False
    if any(not isinstance(x, str) or "\x00" in x for x in argv):
        return False
    binary = os.path.basename(argv[0])
    args = list(argv[1:])
    standard = {"hostname", "uptime", "df", "chage", "systemctl", "service-control", "lsb_release", "uname", "service"}
    special = {"domainjoin-cli": "/opt/likewise/bin/domainjoin-cli",
               "lwregshell": "/opt/likewise/bin/lwregshell",
               "vmon-cli": "/usr/lib/vmware-vmon/vmon-cli",
               "vecs-cli": "/usr/lib/vmware-vmafd/bin/vecs-cli",
               "psql": "/opt/vmware/vpostgres/current/bin/psql",
               "ldconfig": "/sbin/ldconfig"}
    if "/" in argv[0]:
        expected = {"/usr/bin/" + binary, "/bin/" + binary, "/usr/sbin/" + binary} if binary in standard else {special.get(binary)}
        if binary == "service":
            expected.add("/sbin/service")
        if binary == "ldconfig":
            expected = {"/sbin/ldconfig", "/usr/sbin/ldconfig"}
        if argv[0] not in expected:
            return False
    # Runtime dependency probes: distro._lsb_release_info and CPython
    # platform._Processor / ctypes.util. Permit only their read-only forms.
    if binary == "lsb_release":
        return args == ["-a"]
    if binary == "uname":
        return args in (["-p"], ["-rs"])
    if binary == "ldconfig":
        return argv[0] in ("/sbin/ldconfig", "/usr/sbin/ldconfig") and args == ["-p"]
    if binary == "service":
        return args == ["--status-all"] or (len(args) == 2 and args[1] == "status" and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,100}", args[0]) is not None)
    if binary == "hostname":
        return args == ["-f"]
    if binary == "uptime":
        return args == []
    if binary == "df":
        return args in ([], ["-i"])
    if binary == "chage":
        return args == ["-l", "root"]
    if binary == "domainjoin-cli":
        return args == ["query"]
    if binary == "systemctl":
        return len(args) >= 1 and args[0] in ("is-enabled", "status", "is-active", "show") and all(re.fullmatch(r"[a-zA-Z0-9_.@=\-]+", x) for x in args)
    if binary == "service-control":
        return args and args[0] == "--status" and all(re.fullmatch(r"[a-zA-Z0-9_.\-]+", x) for x in args)
    if binary == "vmon-cli":
        return args == ["--list"] or args == ["-l"] or (len(args) == 2 and args[0] in ("--status", "-s") and re.fullmatch(r"[a-zA-Z0-9_.\-]+", args[1]) is not None)
    if binary == "vecs-cli":
        if args == ["store", "list"]:
            return True
        if len(args) == 4 and args[:3] == ["entry", "list", "--store"]:
            return bool(args[3]) and not args[3].startswith("-")
        if len(args) == 6 and args[:3] == ["entry", "getcert", "--store"] and args[4] == "--alias":
            return all(x and not x.startswith("-") for x in (args[3], args[5]))
        return False
    if binary == "lwregshell":
        return args and args[0] in ("list_values", "list_keys", "get_value")
    if binary == "psql":
        if len(args) != 5 or args[:4] != ["-d", "VCDB", "postgres", "-c"]:
            return False
        query = args[-1]
        return bool(re.match(r"\s*select\s", query, re.I)) and ";" not in query.rstrip().rstrip(";") and "\\" not in query
    return False


def audited_command_allowed(executable, argv):
    if not isinstance(executable, (str, bytes)) or not isinstance(argv, (list, tuple)) or not argv:
        return False
    if not isinstance(argv[0], str):
        return False
    executable = os.fsdecode(executable)
    if os.path.basename(executable) != os.path.basename(argv[0]):
        return False
    # Check both the requested argument vector and the real executable; Popen
    # executable= can otherwise disguise an unapproved interpreter as a reader.
    return command_allowed(argv) and command_allowed([executable] + list(argv[1:]))


def audit_policy(root, denials=None):
    write_bits = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    def audit(event, args):
        def deny():
            if denials is not None:
                denials.append(event)
            error = BoundaryViolation()
            audit.last_error = error
            error.audit_event = event
            if event in ("subprocess.Popen", "os.posix_spawn", "os.posix_spawnp"):
                executable = args[0]
                binary = os.path.basename(os.fsdecode(executable)) if isinstance(executable, (str, bytes)) else "runtime"
                error.audit_binary = binary if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", binary) else "runtime"
            raise error
        if event == "open":
            path, mode, flags = args
            if isinstance(path, int):
                return
            writing = (isinstance(flags, int) and flags & write_bits) or (isinstance(mode, str) and any(x in mode for x in "wax+"))
            if writing and os.fsdecode(path) != "/dev/null" and not is_within(path, root):
                deny()
        elif event in ("os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.chown", "os.truncate", "os.utime"):
            if not is_within(args[0], root):
                deny()
            # Refuse dir_fd-relative mutations; resolution otherwise could be misleading.
            if event in ("os.mkdir", "os.remove", "os.rmdir") and isinstance(args[-1], int) and args[-1] != -1:
                deny()
        elif event in ("os.rename", "os.link", "os.symlink"):
            if not is_within(args[0], root) or not is_within(args[1], root):
                deny()
        elif event in ("os.system", "pty.spawn"):
            deny()
        elif event in ("os.posix_spawn", "os.posix_spawnp"):
            executable, argv = args[:2]
            if not audited_command_allowed(executable, argv):
                deny()
        elif event == "subprocess.Popen":
            executable, argv, cwd, environment = args
            if not audited_command_allowed(executable, argv):
                deny()
        elif event == "sqlite3.connect":
            parsed = urlparse(str(args[0]))
            if parsed.scheme != "file" or parse_qs(parsed.query).get("mode") != ["ro"]:
                deny()
    audit.last_error = None
    return audit


def readonly_sqlite():
    original = sqlite3.connect
    def connect(database, *args, **kwargs):
        text = os.fsdecode(database)
        if text.startswith("file:"):
            path = urlparse(text).path
        else:
            path = str(Path(text).resolve())
        kwargs["uri"] = True
        return original("file:" + quote(path, safe="/") + "?mode=ro", *args, **kwargs)
    sqlite3.connect = connect


def fail_prompt(*args, **kwargs):
    raise UnexpectedPrompt()


def auth_bridge(module, username, password):
    attempted = []
    def login(*args, **kwargs):
        if attempted:
            raise CredentialsRequired()
        attempted.append(True)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        manager = None
        try:
            try:
                version = module.newestVersions.GetName("vpx")
            except AttributeError:
                version = module.newestVersions.Get("vpx")
            stub = module.SoapStubAdapter(host="localhost", port=module.httpsPort, path="/sdk", version=version, sslContext=context, httpConnectionTimeout=10)
            manager = module.Vim.ServiceInstance("ServiceInstance", stub).content.sessionManager
            manager.Login(username, password)
        except Exception:
            raise CredentialsRequired() from None
        finally:
            if manager is not None:
                try:
                    manager.Logout()
                except Exception:
                    pass
        return username, password, True, "OK"
    return login


def omit_firstboot_ovf_lookup(tools):
    """Omit only the optional OVF-backed firstboot.stress lookup.

    cis.tools.is_firstboot_stress_enabled already treats a lookup exception as
    False. This preserves that fallback without reading the full OVF envelope,
    which can contain deployment secrets. It is not a diagnostic result.
    """
    original = getattr(tools, "installParamInst", None)
    if original is None or not callable(getattr(original, "getParameter", None)):
        error = RunnerError()
        error.code = "unsupported_runtime"
        error.message = "The appliance install parameter interface differs from the reviewed runtime."
        raise error

    class Parameters:
        def __init__(self, delegate):
            object.__setattr__(self, "_delegate", delegate)

        def getParameter(self, *args, **kwargs):
            if args and args[0] == "firstboot.stress":
                raise LookupError("Optional firstboot stress parameter was not assessed")
            return self._delegate.getParameter(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._delegate, name)

        def __setattr__(self, name, value):
            setattr(self._delegate, name, value)

        def __delattr__(self, name):
            delattr(self._delegate, name)

    tools.installParamInst = Parameters(original)


def run_native(root, data):
    work, artifacts, excluded = prepare_copy(root)
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["TMPDIR"] = str(root)
    os.environ["TMP"] = str(root)
    os.environ["TEMP"] = str(root)
    os.environ["PGOPTIONS"] = "-c default_transaction_read_only=on"
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ.pop("VDT_FORCE", None)
    os.umask(0o077)
    logging.disable(logging.CRITICAL + 100)
    builtins.input = fail_prompt
    import getpass
    getpass.getpass = fail_prompt
    readonly_sqlite()
    denials = []
    policy = audit_policy(root, denials)
    sys.addaudithook(policy)
    sys.path.insert(0, str(work))
    appliance_python = os.environ.get("VMWARE_PYTHON_PATH")
    if appliance_python and appliance_python not in sys.path:
        sys.path.append(appliance_python)
    tools = importlib.import_module("cis.tools")
    omit_firstboot_ovf_lookup(tools)
    # VDT imports native appliance libraries; never import this inside the web process.
    common = importlib.import_module("vcenter.vc_lib.common")
    # Avoid launching the native sso-config shell/Java helper during defaults.
    # Identity-source assessment is outside this reduced collection scope.
    common.get_iwa_sources = lambda: None
    native = importlib.import_module("vcenter.vc_vdt")
    native._update_vm_support = lambda: None
    native.loadMachineCredentials = fail_prompt
    native.prompt = fail_prompt
    native.login_retry_limit = -1
    native.TestLogin = auth_bridge(native, data["sso_username"], data["sso_password"])
    # Verify supplied SSO once even if native service preflight would otherwise skip auth.
    credentials = native.TestLogin()
    native.TestLogin = lambda *args, **kwargs: credentials
    import lib.vdt_base as base
    base.bypass = True
    base.force_prompt = lambda *args, **kwargs: False
    selected = []
    generated = []
    OriginalFormatter = native.Formatter
    class RecordingFormatter(OriginalFormatter):
        def build_output(self):
            selected.extend(self.checks)
            return super().build_output()
        def generate_report(self, *args, **kwargs):
            value = super().generate_report(*args, **kwargs)
            generated.append((self.json_filename, self.report_filename))
            return value
    native.Formatter = RecordingFormatter
    native.main()
    if denials:
        raise policy.last_error or BoundaryViolation()
    if not generated:
        raise RunnerError()
    notes = [
        "Reduced audited vCenter check scope; not full native VDT parity.",
        "Firstboot stress deployment parameter not assessed; optional full OVF environment lookup omitted to avoid deployment secrets.",
        "Support bundle registration disabled. Logs, configuration and artifacts confined to this run directory.",
        "External update, LDAP/AD, lookup service and other non-allowlisted checks were excluded.",
        "SSO credentials validated once without retries; no machine or supervisor credentials extracted.",
        "Native service/version filtering can omit additional checks; absent checks are not passes.",
    ]
    metadata = {"adapter": ADAPTER, "profile": "bounded-vcenter", "scope_notes": notes, "checks_selected": sorted(set(selected)), "checks_excluded": excluded,
                "checks_not_executed": sorted(set(CHECKS) - set(selected)), "source_version": "2.3.2"}
    files = []
    for json_name, text_name in generated[-1:]:
        json_path = Path(json_name)
        text_path = Path(text_name)
        for path in (json_path, text_path):
            if not is_within(path, artifacts) or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
                raise BoundaryViolation()
        try:
            document = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeError):
            raise RunnerError() from None
        if not isinstance(document, dict) or not isinstance(document.get("report"), dict):
            raise RunnerError()
        document["vcfr_collection"] = metadata
        def redact(value):
            if isinstance(value, str):
                return value.replace(data["sso_password"], "[REDACTED]")
            if isinstance(value, list):
                return [redact(item) for item in value]
            if isinstance(value, dict):
                return {redact(key): redact(item) for key, item in value.items()}
            return value
        json_output = json.dumps(redact(document), ensure_ascii=False, indent=2)
        text_output = text_path.read_text(encoding="utf-8")
        # Exact secret redaction is defense in depth, never a substitute for audited checks.
        text_output = text_output.replace(data["sso_password"], "[REDACTED]")
        json_path.write_text(json_output, encoding="utf-8")
        text_path.write_text(text_output, encoding="utf-8")
        files.extend([json_path.relative_to(root).as_posix(), text_path.relative_to(root).as_posix()])
    return {"ok": True, "product": data["product"], "artifact_files": files, "scope_notes": notes}


def failure(error, product=""):
    # Never serialize exception messages, args, source lines, locals or raw
    # subprocess arguments. Names and locations permit prerequisite diagnosis.
    known = isinstance(error, (RunnerError, CredentialsRequired, UnexpectedPrompt))
    record = {"ok": False, "product": product, "artifact_files": [],
              "error_code": error.code if known else "collection_failed",
              "error": error.message if known else RunnerError.message}
    name = type(error).__name__
    record["error_type"] = name[:80] if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name) else "Exception"
    frames = []
    current = error.__traceback__
    while current is not None:
        code = current.tb_frame.f_code
        filename = os.path.basename(code.co_filename)
        function = code.co_name
        frames.append({
            "file": filename[:120] if re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", filename) else "runtime",
            "line": int(current.tb_lineno),
            "function": function[:80] if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", function) else "runtime",
        })
        current = current.tb_next
    record["stack_frames"] = frames[-12:]
    event = getattr(error, "audit_event", None) if isinstance(error, BoundaryViolation) else None
    if event in {"open", "os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.chown", "os.truncate", "os.utime",
                 "os.rename", "os.link", "os.symlink", "os.system", "os.posix_spawn", "os.posix_spawnp", "pty.spawn",
                 "subprocess.Popen", "sqlite3.connect"}:
        record["audit_event"] = event
        binary = getattr(error, "audit_binary", None)
        if event in ("subprocess.Popen", "os.posix_spawn", "os.posix_spawnp") and isinstance(binary, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", binary):
            record["audit_binary"] = binary
    return record


def worker(raw):
    result = None
    root = None
    # Native stdout/stderr, including C extensions, must never enter the transport protocol.
    saved = os.dup(1)
    try:
        with open(os.devnull, "w") as null:
            os.dup2(null.fileno(), 1)
            os.dup2(null.fileno(), 2)
        data = secret_payload(raw)
        root = sandbox_root(Path.cwd())
        result = run_native(root, data)
    except BaseException as error:
        result = failure(error)
    finally:
        pass
    # Leave native stdout/stderr redirected through interpreter atexit handlers.
    os.write(saved, (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))
    os.close(saved)


def supervise(raw):
    try:
        data = secret_payload(raw)
        sandbox_root(Path.cwd())
    except BaseException as error:
        return failure(error)
    child = None
    def cancel(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    try:
        # Block cancellation only across process creation, so the child PID is
        # known before a pending cancellation is delivered to this supervisor.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous),
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        output, _ = child.communicate(raw.encode("utf-8"), timeout=TIMEOUT)
        if child.returncode != 0 or len(output) > MAX_INPUT:
            raise RunnerError()
        try:
            result = json.loads(output.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeError):
            raise RunnerError() from None
        if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
            raise RunnerError()
        return result
    except subprocess.TimeoutExpired:
        error = RunnerError()
        error.code = "timeout"
        error.message = "VDT exceeded its 15 minute collection limit."
        return failure(error, data["product"])
    except KeyboardInterrupt:
        error = RunnerError()
        error.code = "cancelled"
        error.message = "VDT collection cancelled."
        return failure(error, data["product"])
    except BaseException as error:
        return failure(error, data["product"])
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()


def main():
    raw = sys.stdin.read(MAX_INPUT + 1)
    if sys.argv[1:] == ["--worker"]:
        worker(raw)
    elif not sys.argv[1:]:
        sys.stdout.write(json.dumps(supervise(raw), separators=(",", ":")) + "\n")
        sys.stdout.flush()
    else:
        sys.stdout.write(json.dumps(failure(UnexpectedPrompt())) + "\n")


if __name__ == "__main__":
    main()
'''

def appliance_runner_source() -> str:
    """Return the Python 3.9+ appliance-side runner source."""
    return _RUNNER_SOURCE
