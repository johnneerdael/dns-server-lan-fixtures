"""Unsigned, zero-TTL, nonce-scoped DNS fixtures. No external network I/O."""
import re
import struct
import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

SUFFIX = (b"fresh", b"example", b"test", b"")

def fresh_key(query_wire):
    query = dns.message.from_wire(query_wire)
    if not query.question:
        return None
    labels = query.question[0].name.labels
    if len(labels) < 5 or tuple(x.lower() for x in labels[-4:]) != SUFFIX:
        return None
    nonce = labels[-5].decode("ascii")
    if not re.fullmatch("[0-9a-f]{32}", nonce):
        return None
    key = labels[-6].decode("ascii").lower() if len(labels) > 5 else "apex"
    return key, nonce

def _rr(owner, kind, *data, ttl=0):
    return dns.rrset.from_text(owner, ttl, "IN", kind, *data)

def answer_fresh(query_wire: bytes, tcp: bool = False) -> bytes:
    try:
        q = dns.message.from_wire(query_wire)
    except dns.exception.DNSException:
        # Malformed OPT/count tests still receive a bounded FORMERR header.
        if len(query_wire) < 12:
            return b""
        identifier, flags = struct.unpack("!HH", query_wire[:4])
        return struct.pack("!6H", identifier, 0x8001 | (flags & 0x0110), 0, 0, 0, 0)
    r = dns.message.make_response(q)
    r.flags |= dns.flags.AA
    r.flags &= ~(dns.flags.RA | dns.flags.AD)
    if len(q.question) != 1:
        r.set_rcode(dns.rcode.FORMERR)
        return r.to_wire()
    parsed = fresh_key(query_wire)
    if parsed is None:
        r.set_rcode(dns.rcode.REFUSED)
        return r.to_wire()
    key, nonce = parsed
    zone = f"{nonce}.fresh.example.test."
    owner = q.question[0].name.to_text()
    kind = q.question[0].rdtype
    target = lambda name: f"{name}.{zone}"
    soa = lambda: _rr(zone, "SOA", f"{target('ns')} hostmaster.{zone} 2026092101 60 60 3600 0")
    if q.edns > 0:
        r.use_edns(edns=0, payload=1232)
        r.set_rcode(dns.rcode.BADVERS)
        return r.to_wire()
    if q.edns >= 0:
        r.use_edns(edns=0, payload=1232, ednsflags=q.ednsflags & dns.flags.DO)
    # The LAN zone deliberately has no DNSSEC key, signature, or denial records.
    if kind in (43, 46, 47, 48, 50):
        r.authority.append(soa())
    elif key in ("negative", "dnssec-negative"):
        r.set_rcode(dns.rcode.NXDOMAIN)
        r.authority.append(soa())
    elif key in ("nodata", "unsupported"):
        r.authority.append(soa())
    elif key == "refused":
        r.set_rcode(dns.rcode.REFUSED)
    elif key == "referral":
        r.flags &= ~dns.flags.AA
        r.authority.append(_rr(owner, "NS", "ns." + owner))
        r.additional.append(_rr("ns." + owner, "A", "192.0.2.53"))
    elif key in ("cname", "cname-a", "cname-chain", "ad-guid"):
        if key == "cname-chain":
            r.answer.extend([_rr(owner,"CNAME",target("chain-hop")),_rr(target("chain-hop"),"CNAME",target("a"))])
        else:
            r.answer.append(_rr(owner,"CNAME",target("a")))
        if kind == 1:
            r.answer.append(_rr(target("a"),"A","192.0.2.10"))
    elif key.startswith("dname"):
        if key == "dname-child":
            # Use the queried owner as a child, with a proper ancestor DNAME.
            parent = zone
            replacement = f"target.{nonce}.replacement.example.test."
            r.answer.extend([_rr(parent,"DNAME",replacement),_rr(owner,"CNAME",f"dname-child.{replacement}"),_rr(f"dname-child.{replacement}","A","192.0.2.30")])
        else:
            r.answer.append(_rr(owner,"DNAME",target("target-tree")))
    elif key in ("large-512", "large-1232", "near-max"):
        count = {"large-512":4,"large-1232":7,"near-max":240}[key]
        r.answer.append(_rr(owner,"TXT"," ".join('"'+"x"*250+'"' for _ in range(count))))
    elif key == "large-multi-a":
        r.answer.append(_rr(owner,"A",*(f"192.0.2.{i}" for i in range(1,129))))
    elif key == "large-multi-aaaa":
        r.answer.append(_rr(owner,"AAAA",*(f"2001:db8::{i:x}" for i in range(1,129))))
    elif key == "large-srv":
        r.answer.append(_rr(owner,"SRV",*(f"10 {i} 8443 {target('srv-'+str(i))}" for i in range(1,65))))
    elif kind == 1:
        ttl = {"ttl-normal":60,"ttl-high":86400}.get(key,0)
        data = ["192.0.2.10", "192.0.2.11"] if key=="multi-a" else ["192.0.2.10"]
        r.answer.append(_rr(owner,"A",*data,ttl=ttl))
    elif kind == 28:
        data = ["2001:db8::10", "2001:db8::11"] if key=="multi-aaaa" else ["2001:db8::10"]
        r.answer.append(_rr(owner,"AAAA",*data))
    elif kind == 2:
        r.answer.append(_rr(owner,"NS",target("ns")))
        r.additional.append(_rr(target("ns"),"A","192.0.2.53"))
    elif kind == 6:
        r.answer.append(_rr(owner,"SOA",f"{target('ns')} hostmaster.{zone} 2026092101 60 60 3600 0"))
    elif kind == 15:
        r.answer.append(_rr(owner,"MX",f"10 {target('mail')}"))
        r.additional.append(_rr(target("mail"),"A","192.0.2.25"))
    elif kind == 33:
        port = 389 if key in ("ad-ldap","ad-site","ad-pdc") else 88 if key=="ad-kerberos" else 464 if key=="ad-kpasswd" else 3268 if key=="ad-gc" else 8443
        r.answer.append(_rr(owner,"SRV",f"10 60 {port} {target('service')}"))
        r.additional.extend([_rr(target("service"),"A","192.0.2.40"),_rr(target("service"),"AAAA","2001:db8::40")])
    elif kind in (64,65):
        data = f"0 {target('svc')}" if key.endswith("alias") else f'1 {target("svc")} alpn="h2,h3" port=8443 ipv4hint=192.0.2.40 ipv6hint=2001:db8::40'
        r.answer.append(_rr(owner,dns.rdatatype.to_text(kind),data))
    else:
        values = {12:target("a"),13:'"x86_64" "test-fixture"',16:'"fresh DNS evidence fixture"',17:f'hostmaster.{zone} contact.{zone}',18:f'1 {target("service")}',29:'37 47 0.0 N 122 24 0.0 W 10m 1m 10000m 10m',35:'100 10 "U" "E2U+sip" "!^.*$!sip:test@example.invalid!" .',37:'1 0 8 AQIDBA==',44:'1 1 123456789abcdef67890123456789abcdef67890',52:'3 1 1 '+"01"*32,256:'10 1 "https://example.invalid/fixture"',257:'0 issue "ca.invalid"',65280:r'\# 4 DEADBEEF',255:'"minimal ANY observation"'}
        if kind in values:
            r.answer.append(_rr(owner,"TXT" if kind==255 else dns.rdatatype.to_text(kind),values[kind]))
        else:
            r.authority.append(soa())
    size = 65535 if tcp else max(512, min(q.payload, 4096)) if q.edns>=0 else 512
    return r.to_wire(max_size=size, prefer_truncation=True)
