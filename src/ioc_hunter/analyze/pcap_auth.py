"""Authentication / lateral-movement protocol dissectors for the PCAP analyzer.

Two protocols dominate the "attacker is already inside" phase of an
intrusion and both are routinely captured in incident PCAPs:

- **SMB** (TCP/445, or TCP/139 with a NetBIOS session header) — the
  transport for Windows file shares, PsExec/wmiexec lateral movement, and
  in-the-clear **NTLM** authentication. We identify the dialect
  (SMB1 vs SMB2/3), pull the **TREE_CONNECT** UNC path (``\\\\host\\ADMIN$``
  and drive shares are the classic PsExec tell), and — most valuably —
  parse the embedded **NTLMSSP** messages. Pairing a CHALLENGE (type 2)
  with the matching AUTHENTICATE (type 3) on the same flow reconstructs a
  **NetNTLMv2** hash in hashcat ``-m 5600`` format: a crackable credential
  an analyst can hand straight to the IR team (or that an attacker on the
  wire just harvested).

- **Kerberos** (TCP/88 length-prefixed, or UDP/88) — ASN.1/DER encoded.
  A minimal, bounded DER walker pulls the message type, realm, client and
  service principals, and the requested encryption types. From those we
  flag two of the most common AD attacks: **Kerberoasting** (a service
  ticket issued under RC4-HMAC — crackable offline) and **AS-REP
  roasting** (an AS-REQ with no pre-authentication — the account's AS-REP
  is roastable).

Everything here is total: malformed / truncated / hostile bytes degrade
the result to ``None`` or an empty list, never an exception. We never do
TCP reassembly — SMB and Kerberos PDUs of interest (negotiate, session
setup, tree connect, AS/TGS exchanges) fit comfortably inside a single
segment in practice, and the orchestrator already stitches the first
segments per direction for us.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ioc_hunter.analyze.pcap_parse import IPProto, Packet

# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------

SMB_PORTS = frozenset({445, 139})

_SMB1_MAGIC = b"\xffSMB"
_SMB2_MAGIC = b"\xfeSMB"

#: SMB2 command numbers (MS-SMB2 §2.2.1).
_SMB2_COMMANDS = {
    0: "NEGOTIATE",
    1: "SESSION_SETUP",
    2: "LOGOFF",
    3: "TREE_CONNECT",
    4: "TREE_DISCONNECT",
    5: "CREATE",
    6: "CLOSE",
    7: "FLUSH",
    8: "READ",
    9: "WRITE",
    10: "LOCK",
    11: "IOCTL",
    14: "QUERY_DIRECTORY",
    16: "QUERY_INFO",
    17: "SET_INFO",
}

#: SMB2 header flag: response (server → client) when set.
_SMB2_FLAG_RESPONSE = 0x00000001


@dataclass(frozen=True, slots=True)
class SMBRecord:
    dialect: str  # "SMB1" | "SMB2"
    command: int  # SMB2 command number (-1 for SMB1)
    command_name: str
    is_response: bool
    tree_path: str  # UNC path on TREE_CONNECT, else ""


@dataclass(frozen=True, slots=True)
class NTLMMessage:
    msg_type: int  # 1 = NEGOTIATE, 2 = CHALLENGE, 3 = AUTHENTICATE
    target_name: str  # CHALLENGE target (server/domain), else ""
    server_challenge: bytes  # 8 bytes on CHALLENGE, else b""
    domain: str  # AUTHENTICATE
    user: str  # AUTHENTICATE
    workstation: str  # AUTHENTICATE
    nt_response: bytes  # AUTHENTICATE NtChallengeResponse, else b""


def _strip_nbss(payload: bytes) -> bytes:
    """Strip a NetBIOS Session Service header if present (TCP/139, and the
    direct-hosted 445 transport also prefixes a 4-byte length).

    NBSS header: type(1) flags+length(3, big-endian). Session-message type
    is 0x00. We only strip when the declared length matches the remaining
    bytes closely, so we never eat real SMB data by mistake.
    """
    if len(payload) < 4:
        return payload
    if payload[0] != 0x00:
        return payload
    length = (payload[1] << 16) | (payload[2] << 8) | payload[3]
    if 0 < length <= len(payload) - 4:
        return payload[4 : 4 + length]
    # Length doesn't line up — header may be absent; hand back as-is.
    return payload


def is_smb_packet(pkt: Packet) -> bool:
    return pkt.proto == IPProto.TCP and (pkt.src_port in SMB_PORTS or pkt.dst_port in SMB_PORTS)


def dissect_smb(pkt: Packet) -> SMBRecord | None:
    """Parse the dialect + command (+ tree path) out of one SMB segment."""
    if not is_smb_packet(pkt) or not pkt.payload:
        return None
    body = _strip_nbss(pkt.payload)
    if len(body) < 8:
        return None
    if body[:4] == _SMB1_MAGIC:
        cmd = body[4]
        return SMBRecord(
            dialect="SMB1",
            command=-1,
            command_name=f"SMB1_0x{cmd:02x}",
            is_response=bool(body[9] & 0x80) if len(body) > 9 else False,
            tree_path="",
        )
    if body[:4] != _SMB2_MAGIC or len(body) < 64:
        return None
    # SMB2 header (MS-SMB2 §2.2.1.2): magic(4) struct_size(2) credit_charge(2)
    # status(4) command(2) credits(2) flags(4) next(4) message_id(8) ...
    command = struct.unpack("<H", body[12:14])[0]
    flags = struct.unpack("<I", body[16:20])[0]
    is_response = bool(flags & _SMB2_FLAG_RESPONSE)
    tree_path = ""
    if command == 3 and not is_response:  # TREE_CONNECT request
        tree_path = _smb2_tree_path(body)
    return SMBRecord(
        dialect="SMB2",
        command=command,
        command_name=_SMB2_COMMANDS.get(command, f"0x{command:04x}"),
        is_response=is_response,
        tree_path=tree_path,
    )


def _smb2_tree_path(body: bytes) -> str:
    """Extract the UNC path from an SMB2 TREE_CONNECT request.

    Request body (after the 64-byte header): struct_size(2) flags(2)
    path_offset(2) path_length(2) buffer. ``path_offset`` is measured from
    the start of the SMB2 header. The path is UTF-16LE.
    """
    if len(body) < 72:
        return ""
    path_offset = struct.unpack("<H", body[68:70])[0]
    path_length = struct.unpack("<H", body[70:72])[0]
    if path_length == 0 or path_offset + path_length > len(body) or path_length > 1024:
        return ""
    try:
        return body[path_offset : path_offset + path_length].decode("utf-16-le", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return ""


def is_admin_share(unc: str) -> bool:
    """True for ADMIN$ / C$ / drive$ shares — the PsExec lateral-movement tell.

    IPC$ is excluded: it's used for benign RPC named-pipe access and would
    flood an analyst with false positives.
    """
    share = unc.rsplit("\\", 1)[-1].upper()
    if share in {"IPC$", ""}:
        return False
    return share == "ADMIN$" or (share.endswith("$") and len(share) == 2)


# ---------------------------------------------------------------------------
# NTLMSSP
# ---------------------------------------------------------------------------

_NTLMSSP_SIG = b"NTLMSSP\x00"
_NTLM_FLAG_UNICODE = 0x00000001


def _ntlm_field(blob: bytes, base: int, field_off: int) -> bytes:
    """Read a security-buffer field (Len2 MaxLen2 Offset4) and slice it.

    Offsets in NTLM fields are relative to ``base`` (start of the NTLMSSP
    message). Returns the referenced bytes, bounds-checked.
    """
    if field_off + 8 > len(blob):
        return b""
    length = struct.unpack("<H", blob[field_off : field_off + 2])[0]
    offset = struct.unpack("<I", blob[field_off + 4 : field_off + 8])[0]
    start = base + offset
    if length == 0 or start + length > len(blob) or length > 4096:
        return b""
    return blob[start : start + length]


def _ntlm_text(raw: bytes, unicode_flag: bool) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-16-le" if unicode_flag else "latin-1", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return ""


def parse_ntlmssp(payload: bytes) -> list[NTLMMessage]:
    """Find and parse every NTLMSSP message embedded in ``payload``.

    Works on any transport (SMB SESSION_SETUP, HTTP ``Authorization:
    NTLM`` already base64-decoded by the caller, etc) because it keys off
    the unambiguous ``NTLMSSP\\0`` signature rather than the framing.
    """
    out: list[NTLMMessage] = []
    start = 0
    while True:
        base = payload.find(_NTLMSSP_SIG, start)
        if base < 0:
            break
        start = base + 8
        msg = _parse_one_ntlmssp(payload, base)
        if msg is not None:
            out.append(msg)
        if len(out) >= 8:
            break
    return out


def _parse_one_ntlmssp(blob: bytes, base: int) -> NTLMMessage | None:
    if base + 12 > len(blob):
        return None
    msg_type = struct.unpack("<I", blob[base + 8 : base + 12])[0]
    if msg_type == 2:  # CHALLENGE
        if base + 32 > len(blob):
            return None
        flags = struct.unpack("<I", blob[base + 20 : base + 24])[0]
        target = _ntlm_text(_ntlm_field(blob, base, base + 12), bool(flags & _NTLM_FLAG_UNICODE))
        challenge = blob[base + 24 : base + 32]
        return NTLMMessage(
            msg_type=2,
            target_name=target,
            server_challenge=challenge,
            domain="",
            user="",
            workstation="",
            nt_response=b"",
        )
    if msg_type == 3:  # AUTHENTICATE
        if base + 64 > len(blob):
            return None
        flags = struct.unpack("<I", blob[base + 60 : base + 64])[0]
        uni = bool(flags & _NTLM_FLAG_UNICODE)
        nt_resp = _ntlm_field(blob, base, base + 20)
        domain = _ntlm_text(_ntlm_field(blob, base, base + 28), uni)
        user = _ntlm_text(_ntlm_field(blob, base, base + 36), uni)
        workstation = _ntlm_text(_ntlm_field(blob, base, base + 44), uni)
        return NTLMMessage(
            msg_type=3,
            target_name="",
            server_challenge=b"",
            domain=domain,
            user=user,
            workstation=workstation,
            nt_response=nt_resp,
        )
    if msg_type == 1:  # NEGOTIATE — no creds, but useful to know NTLM is in play
        return NTLMMessage(
            msg_type=1,
            target_name="",
            server_challenge=b"",
            domain="",
            user="",
            workstation="",
            nt_response=b"",
        )
    return None


def netntlmv2_hash(
    user: str, domain: str, server_challenge: bytes, nt_response: bytes
) -> str | None:
    """Assemble a hashcat ``-m 5600`` NetNTLMv2 string, or ``None``.

    Format: ``user::domain:ServerChallenge:NTProofStr:blob`` where the NT
    response (NTLMv2) is ``NTProofStr(16) || blob``. We require a >=16-byte
    NT response (the v2 minimum) and an 8-byte server challenge; anything
    shorter is NTLMv1 or malformed and we decline rather than emit junk.
    """
    if len(server_challenge) != 8 or len(nt_response) < 16 or not user:
        return None
    nt_proof = nt_response[:16].hex()
    blob = nt_response[16:].hex()
    sc = server_challenge.hex()
    return f"{user}::{domain}:{sc}:{nt_proof}:{blob}"


# ---------------------------------------------------------------------------
# Kerberos — a small, bounded DER walker
# ---------------------------------------------------------------------------

KERBEROS_PORTS = frozenset({88})

#: Kerberos message types (RFC 4120 §7.5.7), keyed by the APPLICATION tag.
_KRB_MSG_TYPES = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    30: "KRB-ERROR",
}

#: Encryption types (RFC 3961/4120). RC4-HMAC (23/24) is the roastable one.
_KRB_ETYPES = {
    1: "DES-CBC-CRC",
    3: "DES-CBC-MD5",
    17: "AES128-CTS-HMAC-SHA1",
    18: "AES256-CTS-HMAC-SHA1",
    23: "RC4-HMAC",
    24: "RC4-HMAC-EXP",
}
_RC4_ETYPES = frozenset({23, 24})

_DER_MAX_DEPTH = 24
_DER_MAX_NODES = 4096


@dataclass(slots=True)
class _DERNode:
    cls: int  # 0 universal, 1 application, 2 context, 3 private
    constructed: bool
    num: int  # tag number
    content: bytes  # raw content bytes (for primitives / leaf)
    children: list[_DERNode]


def _der_parse(data: bytes, depth: int, budget: list[int]) -> list[_DERNode]:
    """Parse a sequence of DER TLVs into nodes. Bounded in depth + node count.

    ``budget`` is a one-element list used as a shared mutable node counter
    so a pathological nesting can't explode. Returns whatever parsed before
    a malformed byte; never raises.
    """
    nodes: list[_DERNode] = []
    off = 0
    n = len(data)
    while off < n:
        if budget[0] <= 0 or depth > _DER_MAX_DEPTH:
            break
        budget[0] -= 1
        tag = data[off]
        cls = (tag >> 6) & 0x3
        constructed = bool(tag & 0x20)
        num = tag & 0x1F
        off += 1
        if num == 0x1F:  # high-tag-number form — walk continuation bytes
            num = 0
            while off < n and (data[off] & 0x80):
                num = (num << 7) | (data[off] & 0x7F)
                off += 1
            if off < n:
                num = (num << 7) | (data[off] & 0x7F)
                off += 1
        if off >= n:
            break
        length_byte = data[off]
        off += 1
        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            if num_len_bytes == 0 or num_len_bytes > 4 or off + num_len_bytes > n:
                break
            length = int.from_bytes(data[off : off + num_len_bytes], "big")
            off += num_len_bytes
        else:
            length = length_byte
        if off + length > n:
            break
        content = data[off : off + length]
        off += length
        children = _der_parse(content, depth + 1, budget) if constructed else []
        nodes.append(
            _DERNode(cls=cls, constructed=constructed, num=num, content=content, children=children)
        )
    return nodes


def _der_root(data: bytes) -> _DERNode | None:
    nodes = _der_parse(data, 0, [_DER_MAX_NODES])
    return nodes[0] if nodes else None


def _find_context(node: _DERNode, tag: int) -> _DERNode | None:
    """Return the first context-class [tag] child of ``node``."""
    for child in node.children:
        if child.cls == 2 and child.num == tag:
            return child
    return None


def _der_int(node: _DERNode | None) -> int | None:
    """Decode a (possibly context-wrapped) INTEGER node to an int."""
    if node is None:
        return None
    raw = node.content
    if node.constructed and node.children:
        raw = node.children[0].content
    if not raw:
        return None
    return int.from_bytes(raw, "big")


def _der_strings(node: _DERNode | None) -> list[str]:
    """Collect GeneralString (tag 27) leaves under ``node``."""
    if node is None:
        return []
    out: list[str] = []

    def walk(n: _DERNode) -> None:
        if n.cls == 0 and n.num == 27 and not n.constructed:
            out.append(n.content.decode("latin-1", errors="replace"))
        for c in n.children:
            walk(c)

    walk(node)
    return out


@dataclass(frozen=True, slots=True)
class KerberosRecord:
    msg_type: int
    msg_name: str
    realm: str
    cname: str  # client principal ("user" or "user/host")
    sname: str  # service principal ("krbtgt/REALM", "MSSQLSvc/host", ...)
    etypes: tuple[int, ...]  # requested etypes (REQ) or ticket etype (REP)
    preauth: bool  # REQ: PA-ENC-TIMESTAMP present
    ticket_etype: int  # REP: enc-part etype of the issued ticket (-1 if n/a)


def _principal_string(node: _DERNode | None) -> str:
    """PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQ OF }"""
    if node is None:
        return ""
    inner = node.children[0] if (node.constructed and node.children) else node
    parts = _der_strings(_find_context(inner, 1))
    return "/".join(parts)


def dissect_kerberos(payload: bytes, *, tcp: bool) -> KerberosRecord | None:
    """Parse one Kerberos message. ``tcp`` strips the 4-byte length prefix."""
    body = payload
    if tcp:
        if len(body) < 4:
            return None
        rec_len = struct.unpack(">I", body[:4])[0]
        if 0 < rec_len <= len(body) - 4:
            body = body[4 : 4 + rec_len]
    root = _der_root(body)
    if root is None or root.cls != 1:  # must be an APPLICATION tag
        return None
    msg_type = root.num
    name = _KRB_MSG_TYPES.get(msg_type)
    if name is None:
        return None
    seq = root.children[0] if root.children else None
    if seq is None:
        return None
    if msg_type in (10, 12):  # KDC-REQ (AS-REQ / TGS-REQ)
        return _parse_kdc_req(msg_type, name, seq)
    if msg_type in (11, 13):  # KDC-REP (AS-REP / TGS-REP)
        return _parse_kdc_rep(msg_type, name, seq)
    # AP-REQ / AP-REP / KRB-ERROR — surface type only.
    return KerberosRecord(
        msg_type=msg_type,
        msg_name=name,
        realm="",
        cname="",
        sname="",
        etypes=(),
        preauth=False,
        ticket_etype=-1,
    )


def _parse_kdc_req(msg_type: int, name: str, seq: _DERNode) -> KerberosRecord:
    # KDC-REQ: pvno[1] msg-type[2] padata[3] req-body[4]
    padata = _find_context(seq, 3)
    preauth = _padata_has_enc_timestamp(padata)
    body = _find_context(seq, 4)
    realm = cname = sname = ""
    etypes: tuple[int, ...] = ()
    if body is not None:
        inner = body.children[0] if (body.constructed and body.children) else body
        realm_node = _find_context(inner, 2)
        realm = "".join(_der_strings(realm_node))
        cname = _principal_string(_find_context(inner, 1))
        sname = _principal_string(_find_context(inner, 3))
        etypes = _etype_list(_find_context(inner, 8))
    return KerberosRecord(
        msg_type=msg_type,
        msg_name=name,
        realm=realm,
        cname=cname,
        sname=sname,
        etypes=etypes,
        preauth=preauth,
        ticket_etype=-1,
    )


def _parse_kdc_rep(msg_type: int, name: str, seq: _DERNode) -> KerberosRecord:
    # KDC-REP: pvno[0] msg-type[1] padata[2] crealm[3] cname[4] ticket[5] enc-part[6]
    crealm = "".join(_der_strings(_find_context(seq, 3)))
    cname = _principal_string(_find_context(seq, 4))
    ticket = _find_context(seq, 5)
    sname = ""
    ticket_etype = -1
    if ticket is not None:
        # Ticket ::= [APPLICATION 1] SEQ { tkt-vno[0] realm[1] sname[2] enc-part[3] }
        tkt_app = ticket.children[0] if ticket.children else None
        if tkt_app is not None and tkt_app.children:
            tkt_seq = tkt_app.children[0]
            sname = _principal_string(_find_context(tkt_seq, 2))
            ticket_etype = _encrypted_data_etype(_find_context(tkt_seq, 3))
    return KerberosRecord(
        msg_type=msg_type,
        msg_name=name,
        realm=crealm,
        cname=cname,
        sname=sname,
        etypes=(ticket_etype,) if ticket_etype >= 0 else (),
        preauth=False,
        ticket_etype=ticket_etype,
    )


def _padata_has_enc_timestamp(padata: _DERNode | None) -> bool:
    """PA-DATA ::= SEQ { padata-type[1] INTEGER, padata-value[2] OCTET }.

    PA-ENC-TIMESTAMP is type 2. Its presence means the client pre-
    authenticated — i.e. the account is NOT AS-REP roastable.
    """
    if padata is None:
        return False
    seq = padata.children[0] if (padata.constructed and padata.children) else padata
    for entry in seq.children:
        pa_type = _der_int(_find_context(entry, 1))
        if pa_type == 2:
            return True
    return False


def _etype_list(node: _DERNode | None) -> tuple[int, ...]:
    """etype [8] SEQUENCE OF Int32."""
    if node is None:
        return ()
    seq = node.children[0] if (node.constructed and node.children) else node
    out: list[int] = []
    for child in seq.children:
        if child.content:
            out.append(int.from_bytes(child.content, "big"))
    return tuple(out)


def _encrypted_data_etype(node: _DERNode | None) -> int:
    """EncryptedData ::= SEQ { etype[0] Int32, kvno[1] OPT, cipher[2] OCTET }."""
    if node is None:
        return -1
    seq = node.children[0] if (node.constructed and node.children) else node
    val = _der_int(_find_context(seq, 0))
    return val if val is not None else -1


def is_kerberoastable(rec: KerberosRecord) -> bool:
    """TGS-REP whose issued service ticket uses RC4-HMAC → roastable offline.

    We exclude the krbtgt service (that's a TGT, not a service ticket) so
    normal AS exchanges don't false-positive.
    """
    if rec.msg_type != 13:  # TGS-REP
        return False
    if rec.ticket_etype not in _RC4_ETYPES:
        return False
    service = rec.sname.split("/", 1)[0].lower()
    return service != "krbtgt"


def is_asrep_roastable(rec: KerberosRecord) -> bool:
    """AS-REQ with no pre-authentication → the account's AS-REP is roastable."""
    return rec.msg_type == 10 and not rec.preauth


def is_rc4_downgrade(rec: KerberosRecord) -> bool:
    """A REQ that offers RC4 while not offering AES — an etype-downgrade tell."""
    if rec.msg_type not in (10, 12):
        return False
    has_rc4 = any(e in _RC4_ETYPES for e in rec.etypes)
    has_aes = any(e in (17, 18) for e in rec.etypes)
    return has_rc4 and not has_aes and bool(rec.etypes)


def etype_name(etype: int) -> str:
    return _KRB_ETYPES.get(etype, f"etype/{etype}")
