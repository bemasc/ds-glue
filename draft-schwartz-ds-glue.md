---
title: "Authenticated delegation information using DS records"
abbrev: "DS Glue"
docname: draft-schwartz-ds-glue-latest
category: std

ipr: trust200902
area: General
workgroup: dprive
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: B. Schwartz
    name: Benjamin Schwartz
    organization: Google LLC
    email: bemasc@google.com

normative:
  RFC2119:

informative:



--- abstract

This draft describes a mechanism for conveying arbitrary authenticated DNS data from a parent nameserver to a recursive resolver as part of a delegation response.

--- middle

# Conventions and Definitions

{::boilerplate bcp14}

# Background

The DPRIVE working group has been pursuing designs for authenticated encryption of recursive-to-authoritative communication.  Recursive resolvers could enable authenticated encryption most easily and efficiently if they received authenticated information about the target nameserver's configuration during the in-bailiwick delegation that precedes the direct connection.  However, there are several obstacles to this.

## Obstacle 1: Authentication

Glue records in DNS referral responses are unauthenticated.  Parents do not generally provide RRSIGs for these records in their responses, and resolvers do not expect such signatures to be present.  An in-path attacker can modify or remove records in the delegation response without detection.

If the parent zone also implements authenticated encryption, this provides sufficient protection for the glue records, but many important parent zones seem unlikely to implement authenticated encryption in the near future.

## Obstacle 2: Flexibility

Existing nameserver deployments assume that the delegation response includes only a fixed set of existing RR types (NS, A, AAAA, DS, RRSIG, etc.).  These systems are slow to upgrade, and the working group would like to be able to begin deploying authenticated encryption without first requiring a significant change in these parents.

# Proposal

This draft proposes a way to convey glue RRs in DS records, enabling authenticated delivery of arbitrary RR types as part of the delegation response.

There are three main records involved in this process:

* A Source Record to be conveyed, which may be of any RR type and anywhere below the zone cut.
* A Virtual DNSKEY Record encapsulating the Source Record.
* The DSGLUE Record, a DS record derived from the Virtual DNSKEY Record and published in the parent.

## Encoding {#encoding}

To encode a Source Record, a zone operator first transforms it into a Virtual DNSKEY Record as follows:

* Owner Name = The Owner Name of the Source Record relative to the child zone apex.
* Flags = 0x0001, i.e. only SEP (bit 15) is set.
* Protocol = 3
* Algorithm = DS Glue (see IANA registration in {{iana}})
* Public Key = The RR type and canonicalized RDATA of the Source Record ({{!RFC4034, Section 6.2}}).

For example, these Source Records:

~~~
$ORIGIN example.com.
@ 3600 IN NS ns1
       IN NS ns2
       IN NS NS.OTHER.EXAMPLE.
~~~

would be represented as the following Virtual DNSKEY Records:

~~~
; Public Key = \000\002 \003ns1\007example\003com\000
. 300 IN DNSKEY 1 3 $DSGLUE_NUM AAIDbnMxB2V4YW1wbGUDY29tAA==
; Public Key = \000\002 \003ns2\007example\003com\000
. 300 IN DNSKEY 1 3 $DSGLUE_NUM AAIDbnMyB2V4YW1wbGUDY29tAA==
; Public Key = \000\002 \002ns\005other\007example\000
. 300 IN DNSKEY 1 3 $DSGLUE_NUM AAICbnMFb3RoZXIHZXhhbXBsZQA=
~~~

Note that:

* The NS Source Records are "real" records that appear in authoritative Answers and/or delegation glue, but the DNSKEY records are "virtual records" because they do not appear in any zone or response (in this form).
* The Virtual DNSKEY Records' owner name is "." because the Source Records appear at the zone apex.
* The NS RDATA has been converted to lowercase as specified by the canonicalization algorithm.

Having constructed a Virtual DNSKEY Record, the DSGLUE Record is constructed as usual, but always using the VERBATIM digest type {{!I-D.draft-vandijk-dnsop-ds-digest-verbatim}}.  Thus, the DSGLUE Record's wire format RDATA forms the following concatenation:

~~~
Key Tag | Algorithm = DSGLUE | Digest Type = VERBATIM | Digest = (
  DNSKEY owner name = name prefix | DNSKEY RDATA = (
    Flags = 1 | Protocol = 3 | Algorithm = DSGLUE | Public Key = (
      RR Type | RDATA
    )
  )
)
~~~

The DSGLUE record is a real DS record that appears in the usual DS RRSet, whose owner name is the child apex.

> QUESTION: Should we skip the virtual DNSKEY record, and construct the fake DS directly?  This would save 4-6 bytes per RR, but would lose the ability to reuse DNSKEY->DS construction codepaths (unchanged except for a new digest type).

## Interpretation

Upon receiving a delegation response, resolvers implementing this specification SHALL compute the Adjusted Delegation Response as follows:

1. Copy the delegation response.
2. Reverse the encoding process of any DSGLUE records to reconstruct the source RRSets, all carrying the TTL of the DS RRSet.
3. Add each of these reconstructed RRSets to the Adjusted Delegation Response, replacing any RRSet with the same owner name and type.

Resolution then proceeds as usual, using the Adjusted Delegation Response.  When processing the DS RRSet, the recipient will verify the DS RRSIGs as usual, and abort the resolution as Bogus if DNSSEC validation fails.

Resolvers that do not implement this specification will ignore the DSGLUE records due to the unrecognized algorithm.  Thus, these records are safe to use for both signed and unsigned child zones.

Source Records reconstructed from DSGLUE SHOULD be processed exactly like ordinary unauthenticated glue records.  For example, they MAY be cached for use in future delegations but MUST NOT be returned in any responses (c.f. {{Section 5.4.1 of ?RFC2181}}).

## Special case: RR Type = NSEC or NSEC3

Normally, the absence of a particular record in a delegation response is not informative to a resolver.  The corresponding record might still exist in the child zone.  To inform the resolver that a particular RRSet is nonexistent for the purposes of delegation, the zone owner MAY place an NSEC or NSEC3 record in the delegation response.

As with other glue records, an NSEC glue record only affects behavior during delegation following (see example in {{example-nsec}}).

# Examples

For these examples, the macro `$DSGLUE(prefix, source RR type, source RDATA)` constructs a DSGLUE DS record as described in {{encoding}}.

## Out-of-bailiwick referral

An out-of-bailiwick referral contains only NS records, e.g.

~~~
$ORIGIN com.
example 3600 IN NS ns1.example.net.
             IN NS ns2.example.net.
~~~

These Source Records would be encoded in DSGLUE as:

~~~
$ORIGIN com.
example 3600 IN DS $DSGLUE(., NS, ns1.example.net.)
             IN DS $DSGLUE(., NS, ns2.example.net.)
~~~

## In-bailiwick referral

An in-bailiwick referral contains NS records and at least one kind of address record.

~~~
$ORIGIN com.
example    3600 IN NS    ns1.example
                IN NS    ns2.example
ns1.example 600 IN A     192.0.2.1
                IN AAAA  2001:db8::1
ns2.example 600 IN A     192.0.2.2
                IN AAAA  2001:db8::2
~~~

These records would be encoded in DSGLUE as:

~~~
$ORIGIN com.
example 600 IN DS $DSGLUE(., NS, ns1.example.com.)
            IN DS $DSGLUE(., NS, ns2.example.com.)
            IN DS $DSGLUE(ns1., A, 192.0.2.1)
            IN DS $DSGLUE(ns1., AAAA, 2001:db8::1)
            IN DS $DSGLUE(ns2., A, 192.0.2.1)
            IN DS $DSGLUE(ns2., AAAA, 2001:db8::2)
~~~

Note that the differing TTL between RRSets is lost.

## In-bailiwick referral without IPv4 {#example-nsec}

Consider a delegation to a nameserver that is only reachable with IPv6:

~~~
$ORIGIN com.
example    3600 IN NS    ns1.example
ns1.example 600 IN AAAA  2001:db8::1
~~~

A zone in this configuration can optionally use an NSEC DSGLUE record to indicate that there is no IPv4 address:

~~~
$ORIGIN com.
example 600 IN DS $DSGLUE(., NS, ns1.example.com.)
            IN DS $DSGLUE(ns1., AAAA, 2001:db8::1)
            IN DS $DSGLUE(ns1., NSEC, ns1.example.com. AAAA)
~~~

This arrangement prevents an adversary from inserting forged records for ns1.example.com or _dns.ns1.example.com into the delegation response.

Note that although there is an NSEC record denying the existence of A records for ns1.example.com, it is treated as a glue record that only applies during delegation, so such records can still be resolved if they exist.

## Delegation with authenticated encryption

Assuming a SVCB-based signaling mechanism similar to {{?I-D.draft-schwartz-svcb-dns}}, an in-bailiwick referral with support for authenticated encryption is indicated as follows:

~~~
$ORIGIN com.
example 600 IN DS $DSGLUE(., NS, ns1.example.com.)
            IN DS $DSGLUE(ns1., A, 192.0.2.1)
            IN DS $DSGLUE(ns1., AAAA, 2001:db8::1)
            IN DS $DSGLUE(_dns.ns1., SVCB,
                          1 ns1.example.com. alpn=dot)
~~~

### Disabling DANE {#no-dane}

Resolvers check whether a nameserver supports DANE by resolving a TLSA record during the delegation process ({{tlsa}}).  However, this adds unnecessary latency to the delegation if the nameserver does not implement DANE.  As an optimization, such nameservers can add NSEC records to indicate that there is no such TLSA record, e.g.:

~~~
IN DS $DSGLUE(ns1., NSEC, _dns.ns1.example.com. A AAAA)
IN DS $DSGLUE(_dns.ns1., NSEC, ns1.example.com. SVCB)
~~~

# Security Considerations

Resolvers that process DSGLUE MUST perform DNSSEC validation.

Source Records published as DSGLUE have owner names within the child zone, but are signed only by the parent.  This makes them fully authenticated, but provides different cryptographic guarantees than a direct signature by the child.  For example, these records might not appear in any key use logs maintained by the child.

# Operational Considerations

## Publishing DSGLUE records

In order for the child to publish DSGLUE records, the parent must allow the child to publish arbitrary DS records or have specific support for this specification.

If the parent supports CDS {{!RFC8078}}, child zones MAY use CDS to push DSGLUE records into the parent.  Note that CDNSKEY records cannot be used, because (1) the child cannot publish CDNSKEY records with the required owner name and (2) the child cannot guarantee that the parent will use the VERBATIM digest to produce the DS record.

Child zones SHOULD publish all Source Records as ordinary records of the specified type at the indicated owner name, in order to enable revalidation {{?I-D.draft-ietf-dnsop-ns-revalidation}} and simplify debugging.

## Referral response size

When records are present in both ordinary glue and DSGLUE, the response size is approximately doubled.  This could cause performance issues due to response truncation when the initial query is over UDP.

## PKI and DANE for Authenticated Encryption {#tlsa}

> TODO: Move some of this text into a different draft.

Nameservers supporting authenticated encryption MAY indicate any DANE mode, or none at all.

As an optimization, nameservers using DANE MAY place a TLSA record in the DSGLUE to avoid the latency of a TLSA lookup during delegation.  However, child zones should be aware that this adds complexity and delay to the process of TLSA key rotation.

Nameservers that do not support DANE SHOULD add an NSEC or NSEC3 record denying the TLSA record to the DSGLUE, as shown in {{no-dane}}, to avoid an unnecessary delay.

Resolvers that support authenticated encryption MAY implement support for PKI-based authentication, DANE, or both.  PKI-only resolvers MUST nonetheless resolve TLSA records, and MUST NOT require authentication if the DANE mode is DANE-TA(2) or DANE-EE(3) {{!RFC7671}}.  DANE-only resolvers MUST NOT require authentication if the TLSA record does not exist.

# IANA Considerations {#iana}

IANA is requested to add a new entry to the DNS Security Algorithm Numbers registry:

| Number      | Description        | Mnemonic | Zone Signing | Trans. Sec. | Reference       |
|-------------|--------------------|----------|--------------|-------------|-----------------|
| $DSGLUE_NUM | Authenticated Glue | DSGLUE   | N            | ?           | (This document) |

--- back

# Acknowledgments
{:numbered="false"}

Thanks to Paul Hoffman for detailed comments.
