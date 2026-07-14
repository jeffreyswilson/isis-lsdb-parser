"""
isis_lsdb_parser.py — Custom parser for VSP 'show isis lsdb detail' output.

WHY A CUSTOM PARSER (not TextFSM):
    TextFSM is a line-oriented FSM that maps one input line to one output
    field per rule.  It has no concept of nested or repeated sub-structures
    within a single record.  The ISIS LSDB detail output contains deeply
    nested TLV/sub-TLV blocks (up to 50 ISIDs per sub-TLV instance, multiple
    instances per LSP fragment, multiple fragments per logical LSP) that
    TextFSM cannot model without post-processing hacks that would be harder
    to maintain than a purpose-built parser.

INPUT CONTRACT:
    Raw text as yielded by chunker.process_show_commands_file() for the key
    'show isis lsdb detail'.  The chunker has already stripped the leading
    and trailing ={80} boundary lines.  CRLF line endings are present in
    collected files; this module normalises them to LF on entry.

    The file also contains a three-line command-execution header:
        ****...****
        Command Execution Time: ...
        ****...****
    followed by an ISIS LSDB (DETAIL) title banner.  These are skipped
    by the LSP boundary detector.

OUTPUT CONTRACT — two complementary representations:

    parse_lsdb_flat(raw) -> list[dict]
        ONE ROW PER LSP FRAGMENT.  All scalar TLV fields as top-level keys.
        Multi-value fields (adjacencies, ISIDs, prefixes, etc.) are JSON-
        encoded strings — lossless but opaque to a spreadsheet viewer.
        USE CASE: quick human review in Excel/Numbers; single-file export;
        row count equals LSP fragment count (~111 for a typical fabric node).

    parse_lsdb_normalized(raw) -> dict[str, list[dict]]
        SIX TABLES, each fully normalised to one row per atomic entity.
        Foreign key is lsp_id (the LSP fragment ID string).
        USE CASE: relational queries, SQLite ingestion, pandas joins,
        CSV export where every column contains a scalar value.
        Tables: lsp_summary, lsp_adjacencies, lsp_prefixes, lsp_isids,
                lsp_spbm_instance, lsp_multicast.

TLV COVERAGE (as observed in VSP SPBM fabric output):
    TLV:1    Area Addresses
    TLV:22   Extended IS Reachability (adjacencies + SPBM Sub-TLV)
    TLV:129  Protocol Supported
    TLV:135  TE IP Reachability (prefixes) — both Internal and External metric
             types validated across two distinct fabrics
    TLV:137  Hostname
    TLV:144  SPBM — SUB-TLV 1 (instance) and SUB-TLV 3 (ISID table)
    TLV:147  Chassis MAC
    TLV:185  SPBM IPVPN (multicast over VPN)
    TLV:186  SPBM IP Multicast (GRT)

    Unknown TLV numbers pass through the dispatcher silently (active_tlv is
    set but no handler exists).  Body lines are consumed without error.
    This is correct behaviour; extend the dispatch block in _iter_lsp_records
    when new TLV types need to be captured.

VALIDATED AGAINST:
    Fabric 1 — access node, 28-node SPBM ring, 111 LSP fragments, 3129 ISIDs
    Fabric 2 — core/distribution node, larger fabric, 319 LSP fragments,
               6497 ISIDs, up to 3 adjacencies per node, Internal metric
               prefixes (absent in Fabric 1)

KNOWN UNVERIFIED ASSUMPTIONS — to be confirmed when sample data is available:

    1. Level-2 LSPs (_RE_LSP_HEADER):
       The pattern captures Level-(digit) and would match 'Level-2' syntactically,
       but no Level-2 or L1L2 LSPs have been observed in either test fabric
       (both are pure Level-1 SPBM).  Level-2 LSPs may carry different TLV
       types (e.g. TLV:2 IS Reachability, TLV:128 External IP Reachability)
       that are not handled.  If a Level-2 LSP is encountered, the header will
       parse correctly but unrecognised TLV bodies will be silently skipped.
       Verify by running against an L1L2 or backbone node.

    2. LSP header continuation line ordering (_ParseState.header_state):
       The parser assumes the four LSP header lines always appear in fixed
       sequence:
           Level-N LspID: ...   (triggers header_state = 1)
           Chksum: ...          (header_state 1 -> 2)
           Host_name: ...       (header_state 2 -> 3)
           Attributes: ...      (header_state 3 -> 0)
       This sequence holds across both test fabrics.  If a software version
       omits or reorders these lines, header_state stalls at the missed
       transition and subsequent lines are misrouted: a Chksum line arriving
       in header_state 0 is passed to the TLV dispatcher, which ignores it
       (no 'TLV:' prefix); an LSP that never exits header_state != 0 will have
       its TLV body lines silently dropped.  Symptom: LSP record with empty
       chksum/pdu_length/hostname and zero TLV data.  Verify by inspecting a
       release-notes diff for VSP software versions in use.
"""

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Compiled patterns — named here for single-point maintenance.
# All anchored to start-of-line (^) with re.MULTILINE not used; we iterate
# lines explicitly so ^ in splitlines() context means start of each string.
# ---------------------------------------------------------------------------

# LSP fragment header: "Level-1 LspID: 0049.0750.0300.00-00  SeqNum: 0x...  Lifetime: NNN"
# Level-(digit) captures '1' or '2'.  Level-2 syntax is handled but UNVERIFIED —
# no Level-2 LSPs were present in either test fabric (both pure Level-1 SPBM).
# Level-2 LSPs may carry TLV types not covered by current handlers; unrecognised
# TLV bodies will be silently skipped.  See module docstring: KNOWN UNVERIFIED
# ASSUMPTIONS #1.
_RE_LSP_HEADER = re.compile(
    r'^Level-(\d)\s+LspID:\s+(\S+)\s+SeqNum:\s+(\S+)\s+Lifetime:\s+(\d+)'
)

# Second line of LSP header: "        Chksum: 0x2d3   PDU Length: 194"
_RE_CHKSUM = re.compile(r'Chksum:\s+(\S+)\s+PDU Length:\s+(\d+)')

# Third line: "        Host_name: INEVA-BER-TOR61-ASW-A"
_RE_HOSTNAME = re.compile(r'Host_name:\s+(\S+)')

# Fourth line: "        Attributes:     IS-Type 1"
_RE_ATTRIBUTES = re.compile(r'Attributes:\s+(.+)')

# TLV opening line: "TLV:NNN  <description>"
# group(1)=number, group(2)=rest of line (may contain sub-TLV qualifier)
_RE_TLV = re.compile(r'^TLV:(\d+)\s*(.*)')

# TLV:1 area address value line: "                49.0001"
_RE_AREA_ADDR = re.compile(r'^\s+([\da-f.]+)\s*$')

# TLV:22 adjacency neighbor line:
#   "                0049.0750.0400.00 (INEVA-BER-TOR61-ASW-B)       Metric:10"
_RE_ADJ_NEIGHBOR = re.compile(
    r'^\s+(\S+)\s+\(([^)]+)\)\s+Metric:(\d+)'
)

# TLV:22 SPBM Sub-TLV port line: "                                port id: 276 num_port 1"
_RE_ADJ_PORT = re.compile(r'port id:\s+(\d+)\s+num_port\s+(\d+)')

# TLV:135 prefix metric line:
#   "                Metric: 1 Metric Type: External         Prefix Length: 32"
_RE_PREFIX_METRIC = re.compile(
    r'Metric:\s+(\d+)\s+Metric Type:\s+(\S+)\s+Prefix Length:\s+(\d+)'
)

# TLV:135 UP/Down bit line: "                UP/Down Bit: FALSE              Sub TLV Bit: TRUE"
_RE_PREFIX_UPDOWN = re.compile(r'UP/Down Bit:\s+(\S+)')

# TLV:135 IP address line: "                IP Address: 10.30.216.92"
_RE_PREFIX_IP = re.compile(r'IP Address:\s+(\S+)')

# TLV:137 hostname (scalar): "TLV:137 Host_name: INEVA-BER-TOR61-ASW-A"
_RE_TLV137 = re.compile(r'Host_name:\s+(\S+)')

# TLV:147 chassis MAC: "TLV:147 Chassis MAC: 60:49:c1:d8:fc:00"
_RE_TLV147 = re.compile(r'Chassis MAC:\s+(\S+)')

# TLV:144 SUB-TLV 1 (SPBM instance) field lines
_RE_SPBM_INSTANCE   = re.compile(r'Instance:\s+(\d+)')
_RE_SPBM_BRIDGE_PRI = re.compile(r'bridge_pri:\s+(\d+)')
_RE_SPBM_OUI        = re.compile(r'OUI:\s+(\S+)')
_RE_SPBM_VID_TUPLE  = re.compile(
    r'vid tuple\s*:\s*u-bit\s+(\d+)\s+m-bit\s+(\d+)\s+'
    r'ect-alg\s+(\S+)\s+base vid\s+(\d+)'
)

# TLV:144 SUB-TLV 3 (ISID table) field lines
_RE_ISID_INSTANCE = re.compile(r'^\s+Instance:\s+(\d+)')
_RE_ISID_METRIC   = re.compile(r'^\s+Metric:\s+(\d+)')
_RE_ISID_BMAC     = re.compile(r'^\s+B-MAC:\s+(\S+)')
_RE_ISID_BVID     = re.compile(r'^\s+BVID:(\d+)')
_RE_ISID_COUNT    = re.compile(r"^\s+Number of ISID's:(\d+)")
# Individual ISID value with flag: "16000000(Rx)" — may be comma-separated on one line,
# may continue on subsequent indented lines until a blank line or new Instance: block.
_RE_ISID_VALUE    = re.compile(r'(\d+)\((\w+)\)')

# TLV:186 / TLV:185 multicast field lines
_RE_MC_VPN_ISID  = re.compile(r'VSN ISID:(\d+)')
_RE_MC_VPN_BVID  = re.compile(r'BVID\s+:(\d+)')
_RE_MC_METRIC    = re.compile(r'Metric:(\d+)')
_RE_MC_SRC_IP    = re.compile(r'IP Source Address:\s+(\S+)')
_RE_MC_GRP_IP    = re.compile(r'Group Address\s+:\s+(\S+)')
_RE_MC_DATA_ISID = re.compile(r'Data ISID\s+:\s+(\d+)')
_RE_MC_BVID      = re.compile(r'BVID\s+:\s+(\d+)')
_RE_MC_TX        = re.compile(r'TX\s+:\s+(\d+)')
_RE_MC_ROUTE     = re.compile(r'Route Type\s+:\s+(\S+)')


# ---------------------------------------------------------------------------
# Internal dataclass — holds all parsed fields for one LSP fragment.
# Using a dataclass (vs. raw dict) gives us __repr__ for debugging and
# enforces the schema at construction time.  Exported as dict for CSV/JSON.
# ---------------------------------------------------------------------------

@dataclass
class _LspRecord:
    """
    All fields parsed from one LSP fragment.

    An LSP fragment is one 'Level-N LspID: X.X.X.X.XX-NN' block.  A logical
    LSP (one node) may be split across multiple numbered fragments (-00, -01,
    -02, ...) when the PDU size limit is exceeded; all fragments share the
    same base System ID and hostname.

    Multi-value fields are lists of dicts — they are JSON-encoded for the
    flat (Option A) output and exploded to rows for the normalised (Option B)
    output.
    """
    # --- LSP header fields (always present) ---
    level:      str = ''      # '1' or '2'
    lsp_id:     str = ''      # '0049.0750.0300.00-00'
    seq_num:    str = ''      # '0x000302ac'
    lifetime:   str = ''      # seconds remaining as string
    chksum:     str = ''      # '0x2d3'
    pdu_length: str = ''      # bytes
    hostname:   str = ''      # from header line (not TLV:137)
    attributes: str = ''      # 'IS-Type 1'

    # --- Scalar TLVs ---
    area_address:   str = ''  # TLV:1  (one address observed in all samples)
    protocol:       str = ''  # TLV:129 value (e.g. 'SPBM')
    tlv137_hostname:str = ''  # TLV:137 (redundant with header hostname; kept for fidelity)
    chassis_mac:    str = ''  # TLV:147

    # --- Multi-value TLVs (lists of dicts) ---
    adjacencies:    list = field(default_factory=list)
    # Each entry: {neighbor_id, neighbor_name, metric, port_id, num_ports, spbm_metric}

    prefixes:       list = field(default_factory=list)
    # Each entry: {ip_address, prefix_len, metric, metric_type, updown}

    spbm_instances: list = field(default_factory=list)
    # Each entry: {instance, bridge_pri, oui, vid_tuples: [{u_bit, m_bit, ect_alg, base_vid}]}

    isid_blocks:    list = field(default_factory=list)
    # Each entry: {instance, metric, bmac, bvid, isids: [{isid, flag}]}

    multicast:      list = field(default_factory=list)
    # Each entry: {mc_type('GRT'|'VSN'), vsn_isid, bvid, metric, src_ip,
    #              group_ip, data_isid, tx, route_type}


# ---------------------------------------------------------------------------
# Internal parser state machine — one instance per parse pass.
# Perl equivalent: a hash of state variables + a dispatch table keyed on
# current TLV number.  Python dataclass gives named slots without the
# syntactic overhead of a dict.
# ---------------------------------------------------------------------------

class _ParseState:
    """
    Mutable parse context threaded through the line iterator.

    The parser is a single-pass O(n) line iterator implemented as an explicit
    state machine.  State transitions are driven by line content; there is no
    backtracking or lookahead beyond the current line.

    Attributes track the 'currently open' TLV block so that continuation
    lines (ISID values, prefix triplets, adjacency sub-fields) can be
    appended to the correct accumulator without rescanning earlier lines.
    """

    def __init__(self):
        """Initialise all parse-state slots to their between-records defaults."""
        self.records: list[_LspRecord] = []

        # Currently open LSP record; None between records.
        self.current: _LspRecord | None = None

        # Header parse sub-state: tracks which continuation line we expect.
        # 0 = looking for Level-N LspID line
        # 1 = expecting Chksum line
        # 2 = expecting Host_name line
        # 3 = expecting Attributes line
        #
        # UNVERIFIED ASSUMPTION: these four lines always appear in this exact
        # sequence with no intervening lines.  Observed true across two test
        # fabrics (VSP, pure Level-1 SPBM).  If a software version omits or
        # reorders a line, header_state stalls: the missed transition keeps
        # header_state != 0, causing subsequent TLV body lines to be tested
        # against header patterns and silently dropped.  Symptom: LSP record
        # with empty chksum/pdu_length/hostname and all TLV lists empty.
        # See module docstring: KNOWN UNVERIFIED ASSUMPTIONS #2.
        self.header_state: int = 0

        # Currently active TLV number (int) or None.
        self.active_tlv: int | None = None

        # Currently active sub-TLV number (int) or None.
        self.active_sub_tlv: int | None = None

        # Accumulators for multi-line TLV blocks.

        # TLV:22 — currently open adjacency entry (dict) or None.
        self.cur_adj: dict | None = None

        # TLV:135 — partial prefix being assembled across 3 lines.
        self.cur_prefix: dict | None = None

        # TLV:144 SUB-TLV 1 — partial SPBM instance being assembled.
        self.cur_spbm_inst: dict | None = None

        # TLV:144 SUB-TLV 3 — partial ISID block being assembled.
        self.cur_isid_block: dict | None = None

        # TLV:185/186 — partial multicast entry being assembled.
        self.cur_mc: dict | None = None
        self.cur_mc_type: str = ''   # 'GRT' or 'VSN'
        self.cur_mc_vsn_isid: str = ''
        self.cur_mc_vsn_bvid: str = ''

    # ------------------------------------------------------------------
    # Accumulator flush helpers — called when a block boundary is detected.
    # Each helper pushes the completed sub-record into the parent list and
    # resets the accumulator.  Idempotent when accumulator is already None.
    # ------------------------------------------------------------------

    def flush_adj(self):
        """Push completed adjacency dict into current LSP and reset."""
        if self.cur_adj is not None and self.current is not None:
            self.current.adjacencies.append(self.cur_adj)
        self.cur_adj = None

    def flush_prefix(self):
        """Push completed prefix dict into current LSP and reset."""
        if self.cur_prefix is not None and self.current is not None:
            # Only push if we have at minimum an IP address.
            if self.cur_prefix.get('ip_address'):
                self.current.prefixes.append(self.cur_prefix)
        self.cur_prefix = None

    def flush_spbm_inst(self):
        """Push completed SPBM instance dict into current LSP and reset."""
        if self.cur_spbm_inst is not None and self.current is not None:
            self.current.spbm_instances.append(self.cur_spbm_inst)
        self.cur_spbm_inst = None

    def flush_isid_block(self):
        """Push completed ISID block dict into current LSP and reset."""
        if self.cur_isid_block is not None and self.current is not None:
            # Only push if the block contains at least one ISID.
            if self.cur_isid_block.get('isids'):
                self.current.isid_blocks.append(self.cur_isid_block)
        self.cur_isid_block = None

    def flush_mc(self):
        """Push completed multicast entry into current LSP and reset."""
        if self.cur_mc is not None and self.current is not None:
            # Attach VSN envelope fields for TLV:185 entries.
            if self.cur_mc_type == 'VSN':
                self.cur_mc['vsn_isid'] = self.cur_mc_vsn_isid
                self.cur_mc['bvid']     = self.cur_mc_vsn_bvid
            self.cur_mc['mc_type'] = self.cur_mc_type
            self.current.multicast.append(self.cur_mc)
        self.cur_mc = None

    def flush_lsp(self):
        """
        Push completed LSP record into results list and reset current.

        Called when a new Level-N LspID line is encountered (signals end of
        previous record) and at EOF.
        """
        # Flush any open accumulators before sealing the record.
        self.flush_adj()
        self.flush_prefix()
        self.flush_spbm_inst()
        self.flush_isid_block()
        self.flush_mc()
        if self.current is not None:
            self.records.append(self.current)
        self.current = None


# ---------------------------------------------------------------------------
# Line handlers — one function per TLV type.
# Each receives (line: str, state: _ParseState) and mutates state in-place.
# Returning True means "this line was consumed"; False means "pass to
# next handler".  The dispatcher calls handlers in TLV-number order only
# when state.active_tlv matches.
# ---------------------------------------------------------------------------

def _handle_tlv1_line(line: str, state: _ParseState) -> bool:
    """
    TLV:1 — Area Addresses.

    Format (after TLV opening line):
        <16-spaces><area-address>
    Only one area address observed in SPBM fabric output.  If multiple
    addresses appear, last one wins (overwrite acceptable — extend to list
    if multi-area fabric encountered).
    """
    m = _RE_AREA_ADDR.match(line)
    if m and state.current:
        state.current.area_address = m.group(1)
        return True
    return False


def _handle_tlv22_line(line: str, state: _ParseState) -> bool:
    """
    TLV:22 — Extended IS Reachability (adjacencies).

    Block structure per neighbor:
        <16-spaces><neighbor-id> (<name>)       Metric:<N>
                        SPBM Sub TLV:
                                port id: <N> num_port <N>
                                Metric: <N>

    State machine:
        cur_adj is None   -> looking for a neighbor line
        cur_adj is not None -> inside a neighbor block, absorbing sub-TLV lines

    A new neighbor line flushes the previous cur_adj and opens a new one.
    The block ends when a non-continuation line appears (blank or new TLV),
    which triggers flush_adj() in the outer dispatcher.
    """
    # New neighbor line — flush previous, open new.
    m = _RE_ADJ_NEIGHBOR.match(line)
    if m:
        state.flush_adj()
        state.cur_adj = {
            'neighbor_id':   m.group(1),
            'neighbor_name': m.group(2),
            'metric':        m.group(3),
            'port_id':       '',
            'num_ports':     '',
            'spbm_metric':   '',
        }
        return True

    # Port line — only meaningful inside an open adjacency.
    if state.cur_adj is not None:
        mp = _RE_ADJ_PORT.search(line)
        if mp:
            state.cur_adj['port_id']   = mp.group(1)
            state.cur_adj['num_ports'] = mp.group(2)
            return True
        # SPBM Sub-TLV Metric line: "                                Metric: 10"
        # Distinct from TLV:135 metric line by context (active_tlv == 22).
        mm = re.search(r'^\s+Metric:\s+(\d+)\s*$', line)
        if mm:
            state.cur_adj['spbm_metric'] = mm.group(1)
            return True

    return False


def _handle_tlv135_line(line: str, state: _ParseState) -> bool:
    """
    TLV:135 — TE IP Reachability (prefixes).

    Each prefix entry spans exactly three lines:
        Metric: N  Metric Type: <type>  Prefix Length: N
        UP/Down Bit: <bool>             Sub TLV Bit: <bool>
        IP Address: <ip>

    A new 'Metric:' line signals the start of a new prefix entry.
    The entry is flushed when the IP Address line is consumed (three-line
    triplet is complete) or when the TLV block ends.
    """
    # Metric line opens a new prefix entry.
    mm = _RE_PREFIX_METRIC.search(line)
    if mm:
        state.flush_prefix()
        state.cur_prefix = {
            'metric':      mm.group(1),
            'metric_type': mm.group(2),
            'prefix_len':  mm.group(3),
            'updown':      '',
            'ip_address':  '',
        }
        return True

    if state.cur_prefix is not None:
        mu = _RE_PREFIX_UPDOWN.search(line)
        if mu:
            state.cur_prefix['updown'] = mu.group(1)
            return True

        mi = _RE_PREFIX_IP.search(line)
        if mi:
            state.cur_prefix['ip_address'] = mi.group(1)
            # Triplet complete — flush immediately.
            state.flush_prefix()
            return True

    return False


def _handle_tlv144_sub1_line(line: str, state: _ParseState) -> bool:
    """
    TLV:144 SUB-TLV 1 — SPBM Instance.

    Block structure:
        Instance: N
        bridge_pri: N
        OUI: XX-XX-XX
        num of trees: N
        vid tuple : u-bit N m-bit N ect-alg 0xHHHHHH base vid NNNN
        [vid tuple ...]*

    A new 'Instance:' line opens a new SPBM instance entry.  Multiple vid
    tuples are appended to the same entry's 'vid_tuples' list.
    """
    mi = _RE_SPBM_INSTANCE.search(line)
    if mi and 'Instance:' in line:
        state.flush_spbm_inst()
        state.cur_spbm_inst = {
            'instance':   mi.group(1),
            'bridge_pri': '',
            'oui':        '',
            'vid_tuples': [],
        }
        return True

    if state.cur_spbm_inst is not None:
        mb = _RE_SPBM_BRIDGE_PRI.search(line)
        if mb:
            state.cur_spbm_inst['bridge_pri'] = mb.group(1)
            return True

        mo = _RE_SPBM_OUI.search(line)
        if mo:
            state.cur_spbm_inst['oui'] = mo.group(1)
            return True

        mv = _RE_SPBM_VID_TUPLE.search(line)
        if mv:
            state.cur_spbm_inst['vid_tuples'].append({
                'u_bit':    mv.group(1),
                'm_bit':    mv.group(2),
                'ect_alg':  mv.group(3),
                'base_vid': mv.group(4),
            })
            return True

    return False


def _handle_tlv144_sub3_line(line: str, state: _ParseState) -> bool:
    """
    TLV:144 SUB-TLV 3 — ISID Table.

    Block structure (one 'instance block' within the sub-TLV):
        Instance: N
        Metric: N
        B-MAC: XX-XX-XX-XX-XX-XX
        BVID:NNNN
        Number of ISID's:N
                <isid>(<flag>)[,<isid>(<flag>)]*   <- may wrap to continuation lines
                [<isid>(<flag>)[,...]]*             <- continuation: same deep indent

    Multiple instance blocks appear within a single SUB-TLV 3 section.
    A new 'Instance:' line flushes the current block and opens a new one.

    ISID values wrap across lines at 8 per line (observed maximum).
    Continuation lines have the same deep indentation as the first ISID line.
    They are identified by containing ISID-pattern tokens and NOT matching
    any other field pattern.

    ISID flags observed: Rx, Tx, Both, None.
    """
    # New instance block.
    mi = _RE_ISID_INSTANCE.match(line)
    if mi:
        state.flush_isid_block()
        state.cur_isid_block = {
            'instance': mi.group(1),
            'metric':   '',
            'bmac':     '',
            'bvid':     '',
            'isids':    [],
        }
        return True

    if state.cur_isid_block is not None:
        mm = _RE_ISID_METRIC.match(line)
        if mm:
            state.cur_isid_block['metric'] = mm.group(1)
            return True

        mb = _RE_ISID_BMAC.match(line)
        if mb:
            state.cur_isid_block['bmac'] = mb.group(1)
            return True

        mv = _RE_ISID_BVID.match(line)
        if mv:
            state.cur_isid_block['bvid'] = mv.group(1)
            return True

        mc = _RE_ISID_COUNT.match(line)
        if mc:
            # Count line — value already in 'isids' length after parsing;
            # we parse the actual tokens rather than trusting the count field
            # because a mismatch would silently corrupt data.
            return True

        # ISID value lines: deeply indented, contain NNN(FLAG) tokens.
        # Use findall to handle comma-separated multi-value lines and
        # continuation lines with identical format.
        isid_tokens = _RE_ISID_VALUE.findall(line)
        if isid_tokens:
            for isid, flag in isid_tokens:
                state.cur_isid_block['isids'].append({
                    'isid': isid,
                    'flag': flag,
                })
            return True

    return False


def _handle_tlv185_186_line(line: str, state: _ParseState) -> bool:
    """
    TLV:185 (SPBM IPVPN) and TLV:186 (SPBM IP Multicast).

    TLV:186 GRT block structure:
        GRT ISID
                Metric:N
                IP Source Address: <ip>
                Group Address    : <ip>
                Data ISID        : N
                BVID             : N
                TX               : N
                Route Type       : <type>

    TLV:185 VSN block structure:
        VSN ISID:N
        BVID    :N
                Metric:N
                IP Source Address: <ip>
                Group Address    : <ip>
                Data ISID        : N
                TX               : N
        (no Route Type in VSN)

    The outer dispatcher sets state.active_tlv to 185 or 186 before
    these lines arrive.  'GRT ISID' and 'VSN ISID:' lines open new entries.
    """
    # TLV:186 — new GRT entry
    if 'GRT ISID' in line and not _RE_MC_VPN_ISID.search(line):
        state.flush_mc()
        state.cur_mc_type = 'GRT'
        state.cur_mc = {
            'metric': '', 'src_ip': '', 'group_ip': '',
            'data_isid': '', 'bvid': '', 'tx': '', 'route_type': '',
        }
        return True

    # TLV:185 — VSN envelope (outer scope, not a per-entry open)
    mv = _RE_MC_VPN_ISID.search(line)
    if mv:
        state.cur_mc_type    = 'VSN'
        state.cur_mc_vsn_isid = mv.group(1)
        return True

    mb = _RE_MC_VPN_BVID.search(line)
    if mb and state.active_tlv == 185:
        state.cur_mc_vsn_bvid = mb.group(1)
        # TLV:185 has no 'GRT ISID' line to open the inner mc entry.
        # Open it here after we have the VSN envelope.
        if state.cur_mc is None:
            state.cur_mc = {
                'metric': '', 'src_ip': '', 'group_ip': '',
                'data_isid': '', 'bvid': state.cur_mc_vsn_bvid,
                'tx': '', 'route_type': '',
            }
        return True

    if state.cur_mc is not None:
        mm = _RE_MC_METRIC.search(line)
        if mm and 'Metric:' in line:
            state.cur_mc['metric'] = mm.group(1)
            return True

        ms = _RE_MC_SRC_IP.search(line)
        if ms:
            state.cur_mc['src_ip'] = ms.group(1)
            return True

        mg = _RE_MC_GRP_IP.search(line)
        if mg:
            state.cur_mc['group_ip'] = mg.group(1)
            return True

        md = _RE_MC_DATA_ISID.search(line)
        if md:
            state.cur_mc['data_isid'] = md.group(1)
            return True

        mbv = _RE_MC_BVID.search(line)
        if mbv and state.active_tlv == 186:
            state.cur_mc['bvid'] = mbv.group(1)
            return True

        mt = _RE_MC_TX.search(line)
        if mt:
            state.cur_mc['tx'] = mt.group(1)
            return True

        mr = _RE_MC_ROUTE.search(line)
        if mr:
            state.cur_mc['route_type'] = mr.group(1)
            return True

    return False


# ---------------------------------------------------------------------------
# Core line iterator — single pass, O(n).
# ---------------------------------------------------------------------------

def _iter_lsp_records(raw: str) -> Iterator[_LspRecord]:
    """
    Iterate over normalised raw text and yield one _LspRecord per LSP fragment.

    This is the parse engine.  It is a generator so that callers can stream
    records without materialising the full list — useful for very large LSDB
    outputs (this dataset: ~10K lines, ~370KB per device).

    Args:
        raw: Raw text block as returned by chunker.process_show_commands_file()
             for key 'show isis lsdb detail'.  May contain CRLF line endings;
             they are normalised to LF before processing.

    Yields:
        _LspRecord: One record per LSP fragment in input order.
    """
    # Normalise CRLF -> LF.  The chunker contract says it may do this already,
    # but we normalise defensively here because this module can also be called
    # standalone with raw file content.
    text = raw.replace('\r\n', '\n').replace('\r', '\n')
    lines = text.splitlines()

    state = _ParseState()

    for line in lines:

        # ------------------------------------------------------------------
        # LSP header detection — highest priority, checked before TLV dispatch.
        # A 'Level-N LspID:' line always signals end of previous record.
        # ------------------------------------------------------------------
        m_lsp = _RE_LSP_HEADER.match(line)
        if m_lsp:
            # Flush previous record (flush_lsp is idempotent on first call).
            state.flush_lsp()
            # Open new record.
            state.current = _LspRecord(
                level    = m_lsp.group(1),
                lsp_id   = m_lsp.group(2),
                seq_num  = m_lsp.group(3),
                lifetime = m_lsp.group(4),
            )
            state.header_state = 1   # next expect Chksum line
            state.active_tlv     = None
            state.active_sub_tlv = None
            continue

        # Skip lines before any LSP record is opened (file header banner).
        if state.current is None:
            continue

        # ------------------------------------------------------------------
        # LSP header continuation lines (header_state 1-3).
        # These follow immediately after the Level-N line with fixed content.
        # ------------------------------------------------------------------
        if state.header_state == 1:
            m = _RE_CHKSUM.search(line)
            if m:
                state.current.chksum     = m.group(1)
                state.current.pdu_length = m.group(2)
                state.header_state = 2
                continue

        elif state.header_state == 2:
            m = _RE_HOSTNAME.search(line)
            if m:
                state.current.hostname = m.group(1)
                state.header_state = 3
                continue

        elif state.header_state == 3:
            m = _RE_ATTRIBUTES.search(line)
            if m:
                state.current.attributes = m.group(1).strip()
                state.header_state = 0
                continue

        # ------------------------------------------------------------------
        # TLV opening line detection.
        # Resets active TLV and sub-TLV; flushes any open accumulators from
        # the previous TLV block before switching context.
        # ------------------------------------------------------------------
        m_tlv = _RE_TLV.match(line)
        if m_tlv:
            tlv_num  = int(m_tlv.group(1))
            tlv_rest = m_tlv.group(2).strip()

            # Flush accumulators from previous TLV context.
            state.flush_adj()
            state.flush_prefix()
            state.flush_spbm_inst()
            state.flush_isid_block()
            state.flush_mc()

            state.active_tlv     = tlv_num
            state.active_sub_tlv = None

            # Parse scalar TLVs directly from the opening line.
            if tlv_num == 129:
                # "TLV:129 Protocol Supported: SPBM"
                m = re.search(r'Protocol Supported:\s+(\S+)', line)
                if m:
                    state.current.protocol = m.group(1)

            elif tlv_num == 137:
                m = _RE_TLV137.search(line)
                if m:
                    state.current.tlv137_hostname = m.group(1)

            elif tlv_num == 147:
                m = _RE_TLV147.search(line)
                if m:
                    state.current.chassis_mac = m.group(1)

            elif tlv_num == 144:
                # Determine sub-TLV from opening line:
                # "TLV:144 SUB-TLV 1       SPBM INSTANCE:" or
                # "TLV:144 SUB-TLV 3       ISID:"
                ms = re.search(r'SUB-TLV\s+(\d+)', tlv_rest)
                if ms:
                    state.active_sub_tlv = int(ms.group(1))

            continue   # Opening line consumed; body lines follow.

        # ------------------------------------------------------------------
        # TLV body dispatch — route to the appropriate handler based on
        # active_tlv (and active_sub_tlv for TLV:144).
        # ------------------------------------------------------------------
        if state.active_tlv is None:
            continue   # Between records or in preamble banner — skip.

        atv = state.active_tlv

        if atv == 1:
            _handle_tlv1_line(line, state)

        elif atv == 22:
            _handle_tlv22_line(line, state)

        elif atv == 135:
            _handle_tlv135_line(line, state)

        elif atv == 144:
            if state.active_sub_tlv == 1:
                _handle_tlv144_sub1_line(line, state)
            elif state.active_sub_tlv == 3:
                _handle_tlv144_sub3_line(line, state)
            else:
                # Unknown sub-TLV — check if this line reveals the sub-TLV
                # number (happens when a second TLV:144 block opens without
                # an explicit TLV: line, which does not occur in observed data
                # but is defensive).
                ms = re.search(r'SUB-TLV\s+(\d+)', line)
                if ms:
                    # Flush old accumulators before switching sub-TLV.
                    state.flush_spbm_inst()
                    state.flush_isid_block()
                    state.active_sub_tlv = int(ms.group(1))

        elif atv in (185, 186):
            _handle_tlv185_186_line(line, state)

        # TLV:1, 129, 137, 147 are fully handled at the opening line;
        # their body lines (if any) are benign and skipped here.

    # End of input — flush final record.
    state.flush_lsp()

    yield from state.records


# ---------------------------------------------------------------------------
# Public API — Option A: flat (one row per LSP fragment, JSON for arrays)
# ---------------------------------------------------------------------------

def parse_lsdb_flat(raw: str) -> list[dict]:
    """
    Parse 'show isis lsdb detail' output into a flat list of dicts.

    USE CASE:
        Human review in a spreadsheet.  One row per LSP fragment (~111 rows
        for a typical SPBM fabric access node).  All scalar TLV fields appear
        as direct columns.  Multi-value fields (adjacencies, ISIDs, prefixes,
        SPBM instances, multicast entries) are JSON-encoded strings — lossless
        but opaque to a spreadsheet formula.  This is the trade-off for keeping
        everything in a single table.

        If you need to query the multi-value fields, use parse_lsdb_normalized()
        instead.

    LOSSINESS NOTE:
        Scalar fields: none — every field is a direct column.
        Array fields: lossless encoding — JSON strings preserve full structure.
        A spreadsheet user cannot filter on e.g. "all LSPs advertising ISID
        380001" without post-processing the JSON column.  That use case belongs
        to the normalised output.

    Args:
        raw: Raw text block from chunker, CRLF or LF line endings accepted.

    Returns:
        list[dict]: One dict per LSP fragment.  Keys:
            level, lsp_id, seq_num, lifetime, chksum, pdu_length,
            hostname, attributes, area_address, protocol,
            tlv137_hostname, chassis_mac,
            adjacencies_json, prefixes_json, spbm_instances_json,
            isid_blocks_json, multicast_json
    """
    result = []
    for rec in _iter_lsp_records(raw):
        result.append({
            'level':               rec.level,
            'lsp_id':              rec.lsp_id,
            'seq_num':             rec.seq_num,
            'lifetime':            rec.lifetime,
            'chksum':              rec.chksum,
            'pdu_length':          rec.pdu_length,
            'hostname':            rec.hostname,
            'attributes':          rec.attributes,
            'area_address':        rec.area_address,
            'protocol':            rec.protocol,
            'tlv137_hostname':     rec.tlv137_hostname,
            'chassis_mac':         rec.chassis_mac,
            # Multi-value fields JSON-encoded.  compact separators save space.
            'adjacencies_json':    json.dumps(rec.adjacencies,    separators=(',', ':')),
            'prefixes_json':       json.dumps(rec.prefixes,       separators=(',', ':')),
            'spbm_instances_json': json.dumps(rec.spbm_instances, separators=(',', ':')),
            'isid_blocks_json':    json.dumps(rec.isid_blocks,    separators=(',', ':')),
            'multicast_json':      json.dumps(rec.multicast,      separators=(',', ':')),
        })
    return result


# ---------------------------------------------------------------------------
# Public API — Option B: normalised (six tables, one row per atomic entity)
# ---------------------------------------------------------------------------

def parse_lsdb_normalized(raw: str) -> dict[str, list[dict]]:
    """
    Parse 'show isis lsdb detail' output into six normalised tables.

    USE CASE:
        Relational queries, SQLite ingestion, pandas joins, and any scenario
        where every column must contain a scalar value.  Each table has
        'lsp_id' as a foreign key back to the lsp_summary table.

        Typical row counts for a 28-node SPBM fabric (one collector device):
            lsp_summary:      111 rows  (one per LSP fragment)
            lsp_adjacencies:   56 rows  (two uplinks per access node)
            lsp_prefixes:     128 rows  (loopback + mgmt + subnet per node)
            lsp_isids:       3129 rows  (dominant table)
            lsp_spbm_instance: 56 rows  (two vid-tuples per node)
            lsp_multicast:     27 rows  (GRT/VSN multicast registrations)

    Args:
        raw: Raw text block from chunker, CRLF or LF line endings accepted.

    Returns:
        dict[str, list[dict]] with keys:
            'lsp_summary'       — one row per LSP fragment, scalar fields only
            'lsp_adjacencies'   — one row per IS-IS adjacency
            'lsp_prefixes'      — one row per IP prefix
            'lsp_isids'         — one row per ISID registration
            'lsp_spbm_instance' — one row per SPBM vid-tuple
            'lsp_multicast'     — one row per multicast group registration

    Table schemas:

        lsp_summary:
            level, lsp_id, seq_num, lifetime, chksum, pdu_length,
            hostname, attributes, area_address, protocol,
            tlv137_hostname, chassis_mac

        lsp_adjacencies:
            lsp_id, neighbor_id, neighbor_name, metric,
            port_id, num_ports, spbm_metric

        lsp_prefixes:
            lsp_id, ip_address, prefix_len, metric, metric_type, updown

        lsp_isids:
            lsp_id, instance, metric, bmac, bvid, isid, flag

        lsp_spbm_instance:
            lsp_id, instance, bridge_pri, oui, u_bit, m_bit, ect_alg, base_vid

        lsp_multicast:
            lsp_id, mc_type, vsn_isid, src_ip, group_ip,
            data_isid, bvid, tx, route_type, metric
    """
    tables: dict[str, list[dict]] = {
        'lsp_summary':       [],
        'lsp_adjacencies':   [],
        'lsp_prefixes':      [],
        'lsp_isids':         [],
        'lsp_spbm_instance': [],
        'lsp_multicast':     [],
    }

    for rec in _iter_lsp_records(raw):
        lsp_id = rec.lsp_id

        # --- lsp_summary: one row, all scalar fields ---
        tables['lsp_summary'].append({
            'level':           rec.level,
            'lsp_id':          lsp_id,
            'seq_num':         rec.seq_num,
            'lifetime':        rec.lifetime,
            'chksum':          rec.chksum,
            'pdu_length':      rec.pdu_length,
            'hostname':        rec.hostname,
            'attributes':      rec.attributes,
            'area_address':    rec.area_address,
            'protocol':        rec.protocol,
            'tlv137_hostname': rec.tlv137_hostname,
            'chassis_mac':     rec.chassis_mac,
        })

        # --- lsp_adjacencies: one row per neighbor ---
        for adj in rec.adjacencies:
            tables['lsp_adjacencies'].append({
                'lsp_id':        lsp_id,
                'neighbor_id':   adj.get('neighbor_id', ''),
                'neighbor_name': adj.get('neighbor_name', ''),
                'metric':        adj.get('metric', ''),
                'port_id':       adj.get('port_id', ''),
                'num_ports':     adj.get('num_ports', ''),
                'spbm_metric':   adj.get('spbm_metric', ''),
            })

        # --- lsp_prefixes: one row per IP prefix ---
        for pfx in rec.prefixes:
            tables['lsp_prefixes'].append({
                'lsp_id':      lsp_id,
                'ip_address':  pfx.get('ip_address', ''),
                'prefix_len':  pfx.get('prefix_len', ''),
                'metric':      pfx.get('metric', ''),
                'metric_type': pfx.get('metric_type', ''),
                'updown':      pfx.get('updown', ''),
            })

        # --- lsp_isids: one row per ISID across all ISID blocks ---
        # Each isid_block covers one (bmac, bvid, instance, metric) combination;
        # within that block there may be up to 50 individual ISIDs.
        for blk in rec.isid_blocks:
            for isid_entry in blk.get('isids', []):
                tables['lsp_isids'].append({
                    'lsp_id':   lsp_id,
                    'instance': blk.get('instance', ''),
                    'metric':   blk.get('metric', ''),
                    'bmac':     blk.get('bmac', ''),
                    'bvid':     blk.get('bvid', ''),
                    'isid':     isid_entry.get('isid', ''),
                    'flag':     isid_entry.get('flag', ''),
                })

        # --- lsp_spbm_instance: one row per vid-tuple ---
        # Each SPBM instance has N vid-tuples (typically 2 for dual-tree SPBM).
        for inst in rec.spbm_instances:
            for vt in inst.get('vid_tuples', []):
                tables['lsp_spbm_instance'].append({
                    'lsp_id':     lsp_id,
                    'instance':   inst.get('instance', ''),
                    'bridge_pri': inst.get('bridge_pri', ''),
                    'oui':        inst.get('oui', ''),
                    'u_bit':      vt.get('u_bit', ''),
                    'm_bit':      vt.get('m_bit', ''),
                    'ect_alg':    vt.get('ect_alg', ''),
                    'base_vid':   vt.get('base_vid', ''),
                })

        # --- lsp_multicast: one row per multicast group registration ---
        for mc in rec.multicast:
            tables['lsp_multicast'].append({
                'lsp_id':     lsp_id,
                'mc_type':    mc.get('mc_type', ''),
                'vsn_isid':   mc.get('vsn_isid', ''),
                'src_ip':     mc.get('src_ip', ''),
                'group_ip':   mc.get('group_ip', ''),
                'data_isid':  mc.get('data_isid', ''),
                'bvid':       mc.get('bvid', ''),
                'tx':         mc.get('tx', ''),
                'route_type': mc.get('route_type', ''),
                'metric':     mc.get('metric', ''),
            })

    return tables


# ---------------------------------------------------------------------------
# CSV export helpers
# ---------------------------------------------------------------------------

def write_lsdb_flat_csv(raw: str, output_path: Path) -> int:
    """
    Write the flat (Option A) representation to a single CSV file.

    Column order matches parse_lsdb_flat() key order.  The JSON-encoded
    array columns are quoted by the csv module automatically.

    Args:
        raw:         Raw text block from chunker.
        output_path: Destination Path for the CSV file.

    Returns:
        int: Number of rows written (excludes header).
    """
    rows = parse_lsdb_flat(raw)
    if not rows:
        return 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_lsdb_normalized_csvs(raw: str, output_dir: Path) -> dict[str, int]:
    """
    Write all six normalised (Option B) tables to separate CSV files.

    File names match table names: lsp_summary.csv, lsp_adjacencies.csv, etc.
    Files are written even if the table is empty (header-only file) so that
    downstream consumers can always rely on all six files being present.

    Args:
        raw:        Raw text block from chunker.
        output_dir: Directory where CSV files will be written.  Created if
                    it does not exist.

    Returns:
        dict[str, int]: Table name -> row count (excludes header).
    """
    tables = parse_lsdb_normalized(raw)
    output_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}

    # Column order per table — explicit to keep CSV schema stable across
    # devices that may produce empty tables for some TLV types.
    schemas: dict[str, list[str]] = {
        'lsp_summary': [
            'level', 'lsp_id', 'seq_num', 'lifetime', 'chksum', 'pdu_length',
            'hostname', 'attributes', 'area_address', 'protocol',
            'tlv137_hostname', 'chassis_mac',
        ],
        'lsp_adjacencies': [
            'lsp_id', 'neighbor_id', 'neighbor_name', 'metric',
            'port_id', 'num_ports', 'spbm_metric',
        ],
        'lsp_prefixes': [
            'lsp_id', 'ip_address', 'prefix_len', 'metric', 'metric_type', 'updown',
        ],
        'lsp_isids': [
            'lsp_id', 'instance', 'metric', 'bmac', 'bvid', 'isid', 'flag',
        ],
        'lsp_spbm_instance': [
            'lsp_id', 'instance', 'bridge_pri', 'oui',
            'u_bit', 'm_bit', 'ect_alg', 'base_vid',
        ],
        'lsp_multicast': [
            'lsp_id', 'mc_type', 'vsn_isid', 'src_ip', 'group_ip',
            'data_isid', 'bvid', 'tx', 'route_type', 'metric',
        ],
    }

    for table_name, fieldnames in schemas.items():
        rows = tables.get(table_name, [])
        out_path = output_dir / f'{table_name}.csv'
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames,
                                    extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        counts[table_name] = len(rows)

    return counts


# ---------------------------------------------------------------------------
# Standalone smoke-test entry point.
# Usage: python isis_lsdb_parser.py <show_isis_lsdb_detail.txt> [output_dir]
# Prints row counts for all tables and writes CSVs to output_dir (default: /tmp/isis_out).
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    from pprint import pprint

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <input_file> [output_dir]')
        sys.exit(1)

    input_path  = Path(sys.argv[1])
    output_dir  = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('/tmp/isis_out')

    raw_text = input_path.read_text(encoding='utf-8', errors='replace')

    print('=== Flat output (Option A) ===')
    n_flat = write_lsdb_flat_csv(raw_text, output_dir / 'lsp_flat.csv')
    print(f'  lsp_flat.csv: {n_flat} rows')

    # Spot-check first flat record.
    flat = parse_lsdb_flat(raw_text)
    if flat:
        print('\n  First record (scalar fields only):')
        for k, v in flat[0].items():
            if not k.endswith('_json'):
                print(f'    {k}: {v}')
        adj = json.loads(flat[0]['adjacencies_json'])
        print(f'  adjacencies ({len(adj)}): {adj}')

    print('\n=== Normalised output (Option B) ===')
    counts = write_lsdb_normalized_csvs(raw_text, output_dir)
    for table, count in counts.items():
        print(f'  {table}.csv: {count} rows')

    print(f'\nCSVs written to: {output_dir}')


