"""Unsigned, nonce-scoped DNS fixtures with no external network I/O.

Ordinary answers use one record model, including alias and additional-data
follow-ups. Deliberate wire/stream faults live in fresh_transport instead.
"""
import re
import struct

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rcode
import dns.rdatatype
import dns.rrset
from security_records import OPENPGPKEY, SMIMEA

SUFFIX = (b"fresh", b"example", b"test", b"")
TRANSPORT_KEYS = frozenset({
    "split-prefix", "split-body", "bytewise", "request-split-prefix",
    "request-split-body", "request-bytewise", "persistent", "pipeline",
    "reordered", "coalesced", "close-before", "close-prefix", "close-body",
    "length-mismatch", "stall", "duplicate", "trailing", "mismatch-id",
    "mismatch-question", "zero-prefix", "partial-prefix", "partial-body",
})
ADDRESS_KEYS = TRANSPORT_KEYS | {
    "a", "exact", "wildcard", "mixed-case", "long-label", "long-name",
    "ttl-zero", "ttl-normal", "ttl-high", "signed", "do-off", "cd", "ad",
    "any", "nodata", "unsupported",
}
ALIASES = {"cname", "cname-a", "cname-chain", "chain-hop", "ad-guid"}
DNAME_KEYS = {"dname", "dname-child"}


def _name_key(name):
    labels = name.labels
    if len(labels) < 5 or tuple(x.lower() for x in labels[-4:]) != SUFFIX:
        return None
    nonce = labels[-5].lower()
    if not re.fullmatch(b"[0-9a-f]{32}", nonce):
        return None
    try:
        key = labels[-6].decode("ascii").lower() if len(labels) > 5 else "apex"
    except UnicodeDecodeError:
        return None
    return key, nonce.decode("ascii")


def fresh_key(query_wire):
    query = dns.message.from_wire(query_wire)
    return _name_key(query.question[0].name) if query.question else None


def _rr(owner, kind, *data, ttl=0):
    return dns.rrset.from_text(owner, ttl, "IN", kind, *data)


def _soa(zone, owner=None, primary=None):
    return _rr(owner or zone, "SOA", f"{primary or 'ns.' + zone} hostmaster.{zone} 2026092101 60 60 3600 0")


def _error_response(wire, rcode):
    """Recover only bounded question/OPT metadata, never malformed RR data."""
    if len(wire) < 12:
        return b""
    identifier, flags, qcount, answers, authority, additional = struct.unpack("!6H", wire[:12])
    response = dns.message.Message(identifier)
    response.flags = dns.flags.QR | (flags & (0x7800 | dns.flags.RD | dns.flags.CD))
    offset = 12
    try:
        for _ in range(qcount):
            name, used = dns.name.from_wire(wire, offset)
            offset += used
            kind, rdclass = struct.unpack_from("!HH", wire, offset)
            offset += 4
            if qcount == 1 and dns.opcode.from_flags(flags) == dns.opcode.QUERY:
                response.question.append(dns.rrset.RRset(name, rdclass, kind))
        for _ in range(answers + authority + additional):
            _, used = dns.name.from_wire(wire, offset)
            offset += used
            kind, _, ttl, length = struct.unpack_from("!HHIH", wire, offset)
            offset += 10
            if kind == dns.rdatatype.OPT and response.edns < 0:
                response.use_edns(edns=0, payload=1232, ednsflags=ttl & dns.flags.DO)
            offset += length
            if offset > len(wire):
                break
    except (dns.exception.DNSException, struct.error, ValueError):
        pass
    response.set_rcode(rcode)
    return response.to_wire()


def _records(owner, key, zone):
    """Return data at one node; None denotes a nonexistent node."""
    target = lambda label: f"{label}.{zone}"
    exact = owner == dns.name.from_text(target(key))
    # Only these fixture families deliberately synthesize descendant owners.
    if not exact and key not in {"apex", "wildcard", "long-label", "long-name", "target-tree"}:
        return None
    if key == "apex":
        if owner != dns.name.from_text(zone):
            return None
        return [_soa(zone), _rr(owner, "NS", target("ns"))]
    if key in DNAME_KEYS:
        return [_rr(owner, "DNAME", target("target-tree"))]
    if key in ALIASES:
        return [_rr(owner, "CNAME", target("chain-hop" if key == "cname-chain" else "a"))]
    if key in {"ns", "soa"}:
        records = [_rr(owner, "NS", target("ns")), _soa(zone, owner)]
        if key == "ns":
            records.append(_rr(owner, "A", "192.0.2.53"))
        return records
    if key == "additional-ns":
        return [_rr(owner, "NS", target("additional-ns-host")),
                _soa(owner.to_text(), primary=target("additional-ns-host"))]
    additional_addresses = {"additional-mail": "25", "additional-service": "40",
                            "additional-dc": "60", "additional-ns-host": "53"}
    if key in additional_addresses:
        address = additional_addresses[key]
        return [_rr(owner, "A", f"192.0.2.{address}"),
                _rr(owner, "AAAA", f"2001:db8::{address}")]
    if key == "additional-mx":
        return [_rr(owner, "MX", f"10 {target('additional-mail')}")]
    if key in {"additional-srv", "additional-ad"}:
        host, port = ("additional-dc", 389) if key == "additional-ad" else ("additional-service", 8443)
        return [_rr(owner, "SRV", f"10 60 {port} {target(host)}")]
    if key in ADDRESS_KEYS:
        ttl = {"ttl-normal": 60, "ttl-high": 86400}.get(key, 0)
        records = [_rr(owner, "A", "192.0.2.10", ttl=ttl)]
        if key not in {"nodata", "unsupported"}:
            records.append(_rr(owner, "AAAA", "2001:db8::10", ttl=ttl))
        return records
    if key == "aaaa":
        return [_rr(owner, "AAAA", "2001:db8::10")]
    if key == "mail":
        return [_rr(owner, "A", "192.0.2.25")]
    if key in {"service", "svc", "target-tree"} or re.fullmatch(r"srv-(?:[1-9]|[1-5][0-9]|6[0-4])", key):
        address = "30" if key == "target-tree" else "40"
        records = [_rr(owner, "A", f"192.0.2.{address}"), _rr(owner, "AAAA", f"2001:db8::{address}")]
        if key == "svc":
            data = '1 . alpn="h2,h3" port=8443 ipv4hint=192.0.2.40 ipv6hint=2001:db8::40'
            records.extend([_rr(owner, "SVCB", data), _rr(owner, "HTTPS", data)])
        return records
    if key in {"multi-a", "multi-aaaa"}:
        if key == "multi-a":
            return [_rr(owner, "A", "192.0.2.10", "192.0.2.11")]
        return [_rr(owner, "AAAA", "2001:db8::10", "2001:db8::11")]
    if key in {"large-512", "large-1232", "near-max"}:
        count = {"large-512": 4, "large-1232": 7, "near-max": 240}[key]
        return [_rr(owner, "TXT", " ".join('"' + "x" * 250 + '"' for _ in range(count)))]
    if key == "large-multi-a":
        return [_rr(owner, "A", *(f"192.0.2.{i}" for i in range(1, 129)))]
    if key == "large-multi-aaaa":
        return [_rr(owner, "AAAA", *(f"2001:db8::{i:x}" for i in range(1, 129)))]
    if key == "large-srv":
        return [_rr(owner, "SRV", *(f"10 {i} 8443 {target('srv-' + str(i))}" for i in range(1, 65)))]
    if key in {"srv", "ad-ldap", "ad-site", "ad-pdc", "ad-kerberos", "ad-kpasswd", "ad-gc"}:
        port = {"ad-ldap": 389, "ad-site": 389, "ad-pdc": 389, "ad-kerberos": 88,
                "ad-kpasswd": 464, "ad-gc": 3268}.get(key, 8443)
        return [_rr(owner, "SRV", f"10 60 {port} {target('service')}")]
    if key in {"https", "svcb", "https-alias", "svcb-alias"}:
        kind = "HTTPS" if key.startswith("https") else "SVCB"
        data = f"0 {target('svc')}" if key.endswith("alias") else (
            f'1 {target("svc")} alpn="h2,h3" port=8443 ipv4hint=192.0.2.40 ipv6hint=2001:db8::40'
        )
        return [_rr(owner, kind, data)]
    values = {
        "mx": ("MX", f"10 {target('mail')}"),
        "txt": ("TXT", '"fresh DNS evidence fixture"'),
        "ptr": ("PTR", target("a")), "ad-ptr": ("PTR", target("a")),
        "hinfo": ("HINFO", '"x86_64" "test-fixture"'),
        "rp": ("RP", f'hostmaster.{zone} contact.{zone}'),
        "contact": ("TXT", '"Fixture contact metadata"'),
        "afsdb": ("AFSDB", f"1 {target('service')}"),
        "loc": ("LOC", "37 47 0.0 N 122 24 0.0 W 10m 1m 10000m 10m"),
        "naptr": ("NAPTR", '100 10 "U" "E2U+sip" "!^.*$!sip:test@example.invalid!" .'),
        # Experimental CERT format; the payload does not claim to be PKIX.
        "cert": ("CERT", "65280 0 0 AQIDBA=="),
        "sshfp": ("SSHFP", "1 1 123456789abcdef67890123456789abcdef67890"),
        "tlsa": ("TLSA", "3 1 1 " + "01" * 32),
        "openpgpkey": ("OPENPGPKEY", OPENPGPKEY),
        "smimea": ("SMIMEA", SMIMEA),
        "uri": ("URI", '10 1 "https://example.invalid/fixture"'),
        "caa": ("CAA", '0 issue "ca.invalid"'),
        "unknown": ("TYPE65280", r"\# 4 DEADBEEF"),
    }
    if key in values:
        kind, data = values[key]
        return [_rr(owner, kind, data)]
    return None


def _additional(response, records, zone):
    for rrset in records:
        for rr in rrset:
            if rrset.rdtype == dns.rdatatype.NS:
                target = rr.target
            elif rrset.rdtype == dns.rdatatype.MX:
                target = rr.exchange
            elif rrset.rdtype == dns.rdatatype.SRV:
                target = rr.target
            else:
                continue
            parsed = _name_key(target)
            if parsed is None:
                continue
            for address in _records(target, parsed[0], zone) or []:
                if address.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) and address not in response.additional:
                    response.additional.append(address)


def _answer(response, owner, kind, zone):
    # These finite alias chains need at most two CNAME hops and one DNAME.
    for _ in range(4):
        parsed = _name_key(owner)
        if parsed is None:
            return
        key, _ = parsed
        authority_owner = zone
        if key in {"ns", "soa", "additional-ns"}:
            child_zone = dns.name.from_text(f"{key}.{zone}")
            if owner != child_zone or kind != dns.rdatatype.DS:
                authority_owner = child_zone
        authority_soa = (_soa(str(authority_owner), primary=f"additional-ns-host.{zone}")
                         if key == "additional-ns" and str(authority_owner) != zone
                         else _soa(zone, authority_owner))
        cut = dns.name.from_text(f"{key}.{zone}")
        if key in {"referral", "additional-referral"} and not (owner == cut and kind == dns.rdatatype.DS):
            response.flags &= ~dns.flags.AA
            response.authority.append(_rr(cut, "NS", f"ns.{cut}"))
            response.additional.append(_rr(f"ns.{cut}", "A", "192.0.2.53"))
            if key == "additional-referral":
                response.additional.append(_rr(f"ns.{cut}", "AAAA", "2001:db8::53"))
            return
        if key in {"referral", "additional-referral"}:
            response.authority.append(_soa(zone))
            return
        if key == "refused":
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.REFUSED)
            return
        if key in DNAME_KEYS:
            parent = dns.name.from_text(f"{key}.{zone}")
            if owner != parent:
                replacement = dns.name.from_text(f"target-tree.{zone}")
                response.answer.append(_rr(parent, "DNAME", replacement.to_text()))
                try:
                    canonical = owner.relativize(parent).concatenate(replacement)
                except dns.name.NameTooLong:
                    response.set_rcode(dns.rcode.YXDOMAIN)
                    return
                response.answer.append(_rr(owner, "CNAME", canonical.to_text()))
                if kind == dns.rdatatype.CNAME:
                    return
                owner = canonical
                continue
        records = _records(owner, key, zone)
        if records is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(authority_soa)
            return
        cname = next((rr for rr in records if rr.rdtype == dns.rdatatype.CNAME), None)
        if cname is not None:
            response.answer.append(cname)
            if kind in (dns.rdatatype.CNAME, dns.rdatatype.ANY):
                return
            owner = cname[0].target
            continue
        selected = records[:1] if kind == dns.rdatatype.ANY else [rr for rr in records if rr.rdtype == kind]
        if selected:
            response.answer.extend(selected)
            _additional(response, selected, zone)
        else:
            response.authority.append(authority_soa)
        return
    response.set_rcode(dns.rcode.SERVFAIL)


def _encode_response(response, size):
    """Keep RFC 9471's mandatory in-domain glue rule when limiting message size."""
    try:
        return response.to_wire(max_size=size)
    except dns.exception.TooBig:
        wire = response.to_wire(max_size=size, prefer_truncation=True)
    # dnspython treats additional records as optional when truncating. A
    # referral's available in-domain glue is the important exception.
    if not response.answer and not response.flags & dns.flags.AA:
        glue_targets = {rr.target for rrset in response.authority
                        if rrset.rdtype == dns.rdatatype.NS for rr in rrset
                        if rr.target.is_subdomain(rrset.name)}
        required = [rrset for rrset in response.additional
                    if rrset.name in glue_targets and rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)]
        if required:
            sent = dns.message.from_wire(wire)
            if any(rrset not in sent.additional for rrset in required):
                wire = wire[:2] + struct.pack("!H", sent.flags | dns.flags.TC) + wire[4:]
    return wire


def answer_fresh(query_wire: bytes, tcp: bool = False) -> bytes:
    if len(query_wire) < 12:
        return b""
    flags = struct.unpack_from("!H", query_wire, 2)[0]
    if flags & dns.flags.QR:
        return b""
    if dns.opcode.from_flags(flags) != dns.opcode.QUERY:
        # Do not parse UPDATE/NOTIFY bodies as ordinary DNS questions.
        return _error_response(query_wire, dns.rcode.NOTIMP)
    try:
        query = dns.message.from_wire(query_wire)
    except dns.exception.DNSException:
        return _error_response(query_wire, dns.rcode.FORMERR)
    response = dns.message.make_response(query)
    response.flags &= ~(dns.flags.RA | dns.flags.AD)
    if query.edns >= 0:
        response.use_edns(edns=0, payload=1232, ednsflags=query.ednsflags & dns.flags.DO)
    if len(query.question) != 1:
        response.question.clear()
        response.set_rcode(dns.rcode.FORMERR)
    elif query.edns > 0:
        response.set_rcode(dns.rcode.BADVERS)
    else:
        question = query.question[0]
        parsed = _name_key(question.name)
        if parsed is None or question.rdclass not in (dns.rdataclass.IN, dns.rdataclass.ANY):
            response.set_rcode(dns.rcode.REFUSED)
        elif question.rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            response.set_rcode(dns.rcode.REFUSED)
        else:
            response.flags |= dns.flags.AA
            zone = f"{parsed[1]}.fresh.example.test."
            _answer(response, question.name, question.rdtype, zone)
    size = 65535 if tcp else max(512, min(query.payload, 4096)) if query.edns >= 0 else 512
    return _encode_response(response, size)
