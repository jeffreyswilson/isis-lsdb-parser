"""Tests for isis_lsdb_parser using a sanitized single-LSP-fragment fixture."""

from pathlib import Path

from isis_lsdb_parser import parse_lsdb_normalized

FIXTURE = Path(__file__).parent / "fixtures" / "single_lsp_fragment.txt"


def _load():
    raw = FIXTURE.read_text(encoding="utf-8")
    return parse_lsdb_normalized(raw)


def test_lsp_summary():
    tables = _load()
    assert len(tables["lsp_summary"]) == 1
    rec = tables["lsp_summary"][0]
    assert rec["lsp_id"] == "0001.0001.0001.00-00"
#   assert rec["hostname"] == "LAB-ASW-03"
    assert rec["hostname"] == "LAB-ASW-WRONG"
    assert rec["area_address"] == "49.0012"
    assert rec["protocol"] == "SPBM"
    assert rec["chassis_mac"] == "aa:bb:cc:dd:ee:ff"
    assert rec["tlv137_hostname"] == "LAB-ASW-03"


def test_lsp_adjacencies():
    tables = _load()
    adj = tables["lsp_adjacencies"]
    assert len(adj) == 3
    names = {a["neighbor_name"] for a in adj}
    assert names == {"LAB-ASW-01", "LAB-ASW-02", "LAB-ASW-04"}
    assert all(a["metric"] == "10" for a in adj)


def test_lsp_isids():
    tables = _load()
    isids = tables["lsp_isids"]
    assert len(isids) == 3

    by_bvid_and_isid = {(i["bvid"], i["isid"], i["flag"]) for i in isids}
    assert by_bvid_and_isid == {
        ("4052", "16777215", "None"),
        ("4051", "16000000", "Rx"),
        ("4051", "16777215", "None"),
    }


def test_lsp_spbm_instance():
    tables = _load()
    inst = tables["lsp_spbm_instance"]
    assert len(inst) == 2
    base_vids = {row["base_vid"] for row in inst}
    assert base_vids == {"4051", "4052"}


def test_empty_tables():
    tables = _load()
    assert tables["lsp_prefixes"] == []
    assert tables["lsp_multicast"] == []


def test_malformed_header_missing_chksum_line():
    """
    If the Chksum/Host_name/Attributes header continuation lines are missing,
    header_state stalls at 1 and those three fields remain empty. However,
    TLV body lines are NOT blocked by the stalled header_state -- the header
    continuation checks only `continue` on a match, so non-matching lines
    (including TLV: opening lines and their bodies) fall through to normal
    TLV dispatch. This means TLV:1 area_address still parses correctly,
    contrary to the module docstring's KNOWN UNVERIFIED ASSUMPTION #2, which
    overstates the failure mode -- worth a docstring correction.
    """
    raw = (
        "Level-1\tLspID: 0001.0001.0001.00-00 \tSeqNum: 0x0000f1f0 \tLifetime:   336\n"
        "TLV:1\tArea Addresses: 1\n"
        "\t\t49.0012\n"
    )
    tables = parse_lsdb_normalized(raw)

    assert len(tables["lsp_summary"]) == 1
    rec = tables["lsp_summary"][0]
    assert rec["lsp_id"] == "0001.0001.0001.00-00"
    assert rec["chksum"] == ""
    assert rec["hostname"] == ""
    assert rec["attributes"] == ""
    assert rec["area_address"] == "49.0012"  # TLV:1 still parses correctly


def test_empty_input():
    """Empty input produces empty tables, no exception."""
    tables = parse_lsdb_normalized("")
    for table in tables.values():
        assert table == []


def test_garbage_input():
    """Non-LSDB text produces empty tables, no exception."""
    tables = parse_lsdb_normalized("this is not isis output\nat all\n")
    for table in tables.values():
        assert table == []
