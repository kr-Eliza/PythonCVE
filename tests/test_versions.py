from cvewatch.versions import describe, find_product, is_affected, parse_affected

FORTINET = [{"affected": [
    {"vendor": "Fortinet", "product": "FortiOS", "defaultStatus": "unaffected", "versions": [
        {"versionType": "semver", "version": "7.4.0", "lessThanOrEqual": "7.4.2", "status": "affected"},
        {"versionType": "semver", "version": "7.2.0", "lessThanOrEqual": "7.2.6", "status": "affected"},
    ]},
    {"vendor": "Fortinet", "product": "FortiProxy", "defaultStatus": "unaffected", "versions": [
        {"versionType": "semver", "version": "7.2.0", "lessThanOrEqual": "7.2.8", "status": "affected"},
    ]},
]}]

# shape of kernel records: one entry as git commits, one as version numbers
LINUX = [{"affected": [
    {"vendor": "Linux", "product": "Linux", "defaultStatus": "unaffected", "versions": [
        {"version": "c593d26fb5d5", "lessThan": "253f9ea7e8e5", "status": "affected", "versionType": "git"},
    ]},
    {"vendor": "Linux", "product": "Linux", "defaultStatus": "affected", "versions": [
        {"version": "6.8", "status": "affected"},
        {"version": "0", "lessThan": "6.8", "status": "unaffected", "versionType": "semver"},
        {"version": "6.9.10", "lessThanOrEqual": "6.9.*", "status": "unaffected", "versionType": "semver"},
        {"version": "6.10", "lessThanOrEqual": "*", "status": "unaffected", "versionType": "original_commit_for_fix"},
    ]},
]}]


def test_every_product_is_kept():
    products = [p["product"] for p in parse_affected(FORTINET)]
    assert products == ["FortiOS", "FortiProxy"]


def test_inclusive_ranges():
    fortios = find_product(parse_affected(FORTINET), "fortios")
    assert is_affected("7.2.4", fortios) is True
    assert is_affected("7.2.6", fortios) is True
    assert is_affected("7.2.7", fortios) is False
    assert is_affected("7.0.13", fortios) is False


def test_linux_kernel():
    linux = find_product(parse_affected(LINUX), "Linux")
    assert all(r.get("versionType") != "git" for r in linux["versions"])
    assert is_affected("6.8", linux) is True
    assert is_affected("6.9.3", linux) is True       # before the fix in the 6.9 branch
    assert is_affected("6.9.12", linux) is False     # 6.9 branch fixed in 6.9.10
    assert is_affected("6.6.30", linux) is False     # before the bug was introduced
    assert is_affected("6.11", linux) is False       # fixed from 6.10 on


def test_branch_wildcard_and_zeros():
    entry = {"product": "X", "default": "unknown", "versions": [
        {"version": "7.0.0", "lessThanOrEqual": "7.0.*", "status": "affected"}]}
    assert is_affected("7.0.15", entry) is True
    assert is_affected("7.1.3", entry) is False
    assert is_affected("7", entry) is True


def test_hotfixes_and_undecidable_version():
    entry = {"product": "PAN-OS", "default": "unknown", "versions": [
        {"version": "10.2.0", "lessThan": "10.2.9-h1", "status": "affected"}]}
    assert is_affected("10.2.9", entry) is True
    assert is_affected("10.2.9-h1", entry) is False
    assert is_affected("9.1.0", entry) is False  # outside the listed ranges
    no_versions = {"product": "X", "default": "unknown", "versions": []}
    assert is_affected("1.0", no_versions) is None


def test_describe():
    fortios = find_product(parse_affected(FORTINET), "FortiOS")
    assert describe(fortios) == "7.4.0 to 7.4.2, 7.2.0 to 7.2.6"
    assert describe(find_product(parse_affected(LINUX), "Linux")) == "6.8 and later, except fixed versions"


def test_unaffected_products_are_skipped():
    blocks = [{"affected": [
        {"vendor": "Palo Alto Networks", "product": "PAN-OS", "defaultStatus": "unaffected", "versions": [
            {"version": "10.2.0", "lessThan": "10.2.9-h1", "status": "affected"}]},
        {"vendor": "Palo Alto Networks", "product": "Cloud NGFW", "defaultStatus": "unaffected", "versions": [
            {"version": "All", "status": "unaffected"}]},
    ]}]
    assert [p["product"] for p in parse_affected(blocks)] == ["PAN-OS"]
