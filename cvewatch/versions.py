"""Affected products and versions, from the `affected` block of CVE JSON 5 records."""
import json
import re

# ranges of commit hashes (Linux kernel) cannot be compared with a version number
SKIPPED_TYPES = {"git"}
RANGE_KEYS = ("version", "lessThan", "lessThanOrEqual", "status")


def parse_affected(blocks):
    """Affected products with their version ranges.

    The CNA block is used, and CISA (ADP) only when the CNA lists no product, since ADP often
    repeats the same products in lowercase. A product can appear twice (once as git commits,
    once as version numbers), in which case the ranges are merged.
    """
    products = {}
    for block in blocks:
        for entry in block.get("affected") or []:
            product = entry.get("product")
            if not product or product.lower() == "n/a":
                continue
            ranges = [{k: v[k] for k in RANGE_KEYS if k in v}
                      for v in entry.get("versions", []) if v.get("versionType") not in SKIPPED_TYPES]
            if entry.get("versions") and not ranges:
                continue
            item = products.setdefault(product.lower(), {
                "vendor": entry.get("vendor"), "product": product,
                "default": entry.get("defaultStatus", "unknown"), "versions": [],
            })
            if entry.get("defaultStatus"):
                item["default"] = entry["defaultStatus"]
            item["versions"].extend(ranges)
        if products:
            break
    # products only listed to say they are not affected (e.g. Cloud NGFW for PAN-OS)
    return [p for p in products.values()
            if p["default"] == "affected" or any(r.get("status") == "affected" for r in p["versions"])
            or not p["versions"]]


def describe(entry):
    """Readable text for the affected versions of a product."""
    parts = []
    for r in entry["versions"]:
        if r.get("status") != "affected":
            continue
        start = r.get("version", "")
        if "lessThanOrEqual" in r:
            parts.append(f"{start} to {r['lessThanOrEqual']}")
        elif "lessThan" in r:
            parts.append(f"{start} to < {r['lessThan']}")
        else:
            parts.append(start)
    text = ", ".join(p for p in parts if p)
    if entry.get("default") == "affected":
        text = f"{text} and later, except fixed versions" if text else "all except fixed versions"
    return text


def _key(version, strip_zeros=True):
    """'10.2.9-h1' -> ((1, 10), (1, 2), (1, 9), (0, 'h'), (1, 1)), trailing zeros dropped (7.0.0 == 7)."""
    tokens = re.findall(r"\d+|[a-zA-Z]+", str(version))
    key = [(1, int(t)) if t.isdigit() else (0, t.lower()) for t in tokens]
    while strip_zeros and key and key[-1] == (1, 0):
        key.pop()
    return tuple(key)


def _below(version, bound, inclusive):
    if bound == "*":
        return True
    if bound.endswith(".*"):
        # '6.6.*': the whole 6.6 branch
        prefix = _key(bound[:-2], strip_zeros=False)
        return _key(version, strip_zeros=False)[:len(prefix)] <= prefix
    return _key(version) <= _key(bound) if inclusive else _key(version) < _key(bound)


def _matches(version, r):
    start = r.get("version", "")
    if start.lower() in ("all", "*"):
        return True
    if "lessThan" in r or "lessThanOrEqual" in r:
        bound = r.get("lessThanOrEqual", r.get("lessThan"))
        above = start in ("", "0") or _key(version) >= _key(start)
        return above and _below(version, bound, "lessThanOrEqual" in r)
    return _key(version) == _key(start)


def is_affected(version, entry):
    """True / False, or None when the record does not allow a decision."""
    matched = [r.get("status") for r in entry["versions"] if _matches(version, r)]
    if "unaffected" in matched:
        return False
    if "affected" in matched:
        return True
    default = {"affected": True, "unaffected": False}.get(entry.get("default"))
    if default is None and any(r.get("status") == "affected" for r in entry["versions"]):
        # no default status, but affected ranges are listed: outside them means not affected
        return False
    return default


def find_product(affected, product):
    """Entry for the product (case-insensitive) in the `affected` list, or None."""
    for entry in affected:
        if entry["product"].lower() == product.lower():
            return entry
    return None


def dumps(affected):
    return json.dumps(affected, ensure_ascii=False, separators=(",", ":"))


def loads(value):
    if not isinstance(value, str) or not value.startswith("["):
        return []
    try:
        return json.loads(value)
    except ValueError:
        return []
