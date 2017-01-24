#!/usr/bin/env python
import sys
import dns.message
import dns.flags
import dns.name
import dns.rdatatype
import dns.query
import dns.resolver

default_resolver = dns.resolver.get_default_resolver()

def query_additional(domain, rdtype=dns.rdatatype.ANY, nameservers=None, use_tcp=True):
    if isinstance(domain, str):
        raise TypeError('domain is str')
        #domain = dns.name.from_text(domain)

    if nameservers is None:
        nameservers = default_resolver.nameservers
        if not domain.is_absolute():
            # TODO: process resolver.search
            pass

    request = dns.message.make_query(domain, rdtype)
    request.flags |= dns.flags.AD
    ADDITIONAL_RDCLASS = 4096
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                       dns.rdatatype.OPT, create=True, force_unique=True)

    if use_tcp:
        fetcher = dns.query.tcp
    else:
        fetcher = dns.query.udp

    nameserver = nameservers[0]
    response = fetcher(request, nameserver)
    return response

def query_any(domain, nameservers=None, use_tcp=True):
    return query_additional(domain, dns.rdatatype.ANY, nameservers=nameservers, use_tcp=use_tcp)

def query_soa(domain, nameservers=None, use_tcp=True):
    return query_additional(domain, dns.rdatatype.SOA, nameservers=nameservers, use_tcp=use_tcp)

def query_ns(domain, nameservers=None, use_tcp=True):
    return query_additional(domain, dns.rdatatype.NS, nameservers=nameservers, use_tcp=use_tcp)


def get_zone(domain):
    resp = query_soa(domain)
    zone = None
    for rrset in resp.authority + resp.answer:
        for rr in rrset:
            if rr.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS):
                rr_zone = rrset.name

            if zone is None:
                zone = rr_zone
            else:
                assert zone == rr_zone  # does this happen?

    return zone

def get_nameservers(zone, nameservers=None):
    resp = query_ns(zone, nameservers=nameservers)

    nameservers = []
    for rrset in resp.answer:
        if rrset.name != zone:
            continue

        nameservers += [rr.target.to_unicode() for rr in rrset
                       if rr.rdtype == dns.rdatatype.NS]

    return nameservers

def get_soa(domain, zone=None, nameservers=None):
    resp = query_soa(domain, nameservers=nameservers)

    soa = None
    for rrset in resp.answer + resp.authority:
        if zone is not None and rrset.name != zone:
            continue

        rr_soa = [rr for rr in rrset if rr.rdtype == dns.rdatatype.SOA]
        if not rr_soa:
            continue

        if soa is None:
            soa = rr_soa
            assert len(rr_soa) == 1

        else:
            assert soa == rr_soa

    return soa[0]

def get_with_soa(domain, rdtype=None):
    if rdtype is None:
        rdtype = dns.rdatatype.ANY

    zone = get_zone(domain)
    nameservers = get_nameservers(zone)
    results = []
    for nameserver in nameservers:
        soa = get_soa(domain, zone, nameservers=[nameserver])

        resp = query_additional(domain, rdtype, nameservers=[nameserver])
        answers = []
        for rrset in resp.answer:
            if rrset.name != domain:
                continue

            answers += [(rrset.ttl, rr) for rr in rrset]

        answers = sorted(answers)
        results.append((nameserver, soa, answers))

    return results



for hostname in open(sys.argv[1]):
    results = get_with_soa(dns.name.from_text(hostname.strip()))

    unique_soas = set([(soa.serial, soa.refresh, soa.minimum) for ns, soa, answers in results])
    unique_as = set([tuple([(ttl, a.address) for ttl, a in answers if a.rdtype == dns.rdatatype.A])
                     for ns, soa, answers in results])

    if len(unique_soas) == 1 and len(unique_as) == 1:
        ns, soa, answers = results[0]
        print '%s: %s responded with serial %s refresh %s minimum %s' % (
              hostname, len(results), soa.serial, soa.refresh, soa.minimum)

        for ttl, answer in answers:
            if answer.rdtype == dns.rdatatype.A:
                print '%s %s' % (ttl, answer.address)

    else:
        for ns, soa, answers in results:
            print '%s: %s responded with serial %s refresh %s minimum %s' % (
                  hostname, ns, soa.serial, soa.refresh, soa.minimum)

            for ttl, answer in answers:
                if answer.rdtype == dns.rdatatype.A:
                    print '%s %s' % (ttl, answer.address)

