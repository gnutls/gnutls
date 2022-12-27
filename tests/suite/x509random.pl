#!/usr/bin/perl -w
#
# Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
# Written by David Howells (dhowells@redhat.com)
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <https://www.gnu.org/licenses/>.
#
# Generate validly formatted X.509 certificates filled with mostly random data,
# including for the RSA key and signature fields (so it is extremely improbable
# that key will be useful and the signature will verify).
#
# If an argument of any sort is passed this will cause random bytes to be
# inserted into the ASN.1 structure (whilst keeping the lengths of the wrapping
# constructed elements correct).
#
# Format:
#
#	x509random.pl [-i] >output
#
use strict;

#print STDERR "SEED: ", srand(), "\n";

my $do_inject = ($#ARGV == 0);

my $UNIV = 0 << 6;
my $APPL = 1 << 6;
my $CONT = 2 << 6;
my $PRIV = 3 << 6;

my $BOOLEAN	= 0x01;
my $INTEGER	= 0x02;
my $BIT_STRING	= 0x03;
my $OCTET_STRING = 0x04;
my $NULL	= 0x05;
my $OBJ_ID	= 0x06;
my $UTF8String	= 0x0c;
my $SEQUENCE	= 0x10;
my $SET		= 0x11;
my $UTCTime	= 0x17;
my $GeneralizedTime = 0x18;

sub maybe($)
{
    return (int(rand(6)) == 0) ? '' : $_[0];
}

###############################################################################
#
# Generate a header
#
###############################################################################
sub emit_asn1_hdr($$)
{
    my ($tag, $len) = @_;
    my $output = "";
    my $l;

    if ($len < 0x80) {
	$l = $len;
    } elsif ($len <= 0xff) {
	$l = 0x81;
    } elsif ($len <= 0xffff) {
	$l = 0x82;
    } elsif ($len <= 0xffffff) {
	$l = 0x83;
    } else {
	$l = 0x84;
    }

    $output .= pack("CC", $tag == -1 ? int(rand(255)) & ~0x20 : $tag, $l);
    if ($len < 0x80) {
    } elsif ($len <= 0xff) {
	$output .= pack("C", $len);
    } elsif ($len <= 0xffff) {
	$output .= pack("n", $len);
    } elsif ($len <= 0xffffff) {
	$output .= pack("Cn", $len >> 16, $len & 0xffff);
    } else {
	$output .= pack("N", $len);
    }

    return $output;
}

###############################################################################
#
# Generate random data
#
###############################################################################
sub emit_random_data($$)
{
    my ($minlen, $maxlen) = @_;
    my $output = '';

    my $len = $minlen + int(rand($maxlen - $minlen));

    my $i = $len;
    while ($i > 16) {
	$output .= "abcdefghijklmnop";
	$i -= 16;
    }

    $output .= substr("abcdefghijklmnop", 0, $i);
    return $output;
}

###############################################################################
#
# Generate a primitive containing some random data
#
###############################################################################
sub emit_asn1_prim(@)
{
    my ($class, $tag, $minlen, $maxlen) = @_;
    my $content;

    $minlen = 0 if (!$minlen);
    $maxlen = 255 if (!$maxlen);
    $content = ($tag == $NULL) ? '' : emit_random_data($minlen, $maxlen);

    $tag |= $class;
    return emit_asn1_hdr($tag, length($content)) . $content;
}

###############################################################################
#
# Generate an object identifier
#
###############################################################################
my %OIDs = (
    commonName => pack("CCC", 85, 4, 3),
    countryName => pack("CCC", 85, 4, 6),
    organizationName => pack("CCC", 85, 4, 10),
    organizationUnitName => pack("CCC", 85, 4, 11),
    rsaEncryption => pack("CCCCCCCCC", 42, 134, 72, 134, 247, 13, 1, 1, 1),
    sha1WithRSAEncryption => pack("CCCCCCCCC", 42, 134, 72, 134, 247, 13, 1, 1, 5),
    authorityKeyIdentifier => pack("CCC", 85, 29, 35),
    subjectKeyIdentifier => pack("CCC", 85, 29, 14),
    basicConstraints => pack("CCC", 85, 29, 19)
);

sub emit_asn1_OID($$$)
{
    my ($class, $tag, $oid_name) = @_;
    my $oid;
    my $len;

    if (!exists($OIDs{$oid_name})) {
	print STDERR "Unknown OID: $oid_name\n";
	exit(2);
    }

    $oid = $OIDs{$oid_name};
    $len = length($oid);

    $tag |= $class;

    return emit_asn1_hdr($tag, $len) . $oid;
}

###############################################################################
#
# Generate a UTC time
#
###############################################################################
sub emit_asn1_utctime($$)
{
    my ($class, $tag) = @_;
    my $output = "";
    my $len;

    for (my $i = 0; $i < 12; $i++) {
	$output .= pack("C", int(rand(9)) + 0x30);
    }
    $output .= 'Z';

    $len = length($output);

    $tag |= $class;

    return emit_asn1_hdr($tag, $len) . $output;
}

###############################################################################
#
# Generate a generalized time
#
###############################################################################
sub emit_asn1_gentime($$)
{
    my ($class, $tag) = @_;
    my $output = "";
    my $len;

    for (my $i = 0; $i < 14; $i++) {
	$output .= pack("C", int(rand(9)) + 0x30);
    }
    $output .= 'Z';

    $len = length($output);

    $tag |= $class;

    return emit_asn1_hdr($tag, $len) . $output;
}

###############################################################################
#
# Generate a construct
#
###############################################################################
sub emit_asn1_cons($$$)
{
    my ($class, $tag, $content) = @_;
    my $inject = '';

    if ($do_inject) {
	if (int(rand(20)) == 0) {
	    $inject = pack("C", int(rand(255)));
	}
    }

    $tag |= $class | 0x20;
    return emit_asn1_hdr($tag, length($content)) . $content . $inject;
}

###############################################################################
#
# Generate a name
#
###############################################################################
sub emit_x509_AttributeValueAssertion($@)
{
    my ($type, $min, $max) = @_;
    my $output;
    $output  = emit_asn1_OID($UNIV, $OBJ_ID, $type);	# attributeType
    $output .= emit_asn1_prim($UNIV, $UTF8String, $min, $max);	# attributeValue
    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_RelativeDistinguishedName()
{
    my $output;
    # Set of AttributeValueAssertion
    $output  = emit_x509_AttributeValueAssertion("countryName", 2, 2);
    $output .= emit_x509_AttributeValueAssertion("organizationName", 3, 10);
    $output .= emit_x509_AttributeValueAssertion("organizationUnitName", 3, 10);
    $output .= emit_x509_AttributeValueAssertion("commonName", 4, 16);
    return emit_asn1_cons($UNIV, $SET, $output);
}

sub emit_x509_Name()
{
    my $output;
    # Sequence of RDN
    $output  = emit_x509_RelativeDistinguishedName();
    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

###############################################################################
#
# Generate some X.509 extensions
#
###############################################################################
sub emit_x509_SubjectKeyIdentifier()
{
    my $content = emit_asn1_prim($UNIV, $OCTET_STRING, 10, 20);
    return $content;
}

sub emit_x509_AuthorityKeyIdentifier()
{
    my $content = emit_asn1_prim($CONT, 0, 10, 20);
    my $wrapper = emit_asn1_cons($UNIV, $SEQUENCE, $content);
    return $wrapper;
}

sub emit_x509_BasicConstraints()
{
    my $content = emit_asn1_prim($UNIV, $BIT_STRING, 1, 7);
    return $content;
}

sub emit_x509_Extension($)
{
    my ($ext) = @_;
    my $output;
    my $value = "";

    if ($ext eq "authorityKeyIdentifier") {
	$output = emit_asn1_OID($UNIV, $OBJ_ID, $ext);
	$value = emit_x509_AuthorityKeyIdentifier();
    } elsif ($ext eq "subjectKeyIdentifier") {
	$output = emit_asn1_OID($UNIV, $OBJ_ID, $ext);
	$value = emit_x509_SubjectKeyIdentifier();
    } elsif ($ext eq "basicConstraints") {
	$output = emit_asn1_OID($UNIV, $OBJ_ID, $ext);
	$value = emit_x509_BasicConstraints();
    } else {
	$output = emit_asn1_prim($UNIV, $OBJ_ID, 3, 10);
	$value = emit_random_data(10, 20);
    }

    $output .= maybe emit_asn1_prim($UNIV, $BOOLEAN, 1, 1);	# critical
    $output .= emit_asn1_hdr($UNIV | $OCTET_STRING, length($value)) . $value;

    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_Extensions()
{
    my $output = "";

    # Probably do want a sequence of extensions here
    $output .= maybe emit_x509_Extension("authorityKeyIdentifier");
    $output .= maybe emit_x509_Extension("subjectKeyIdentifier");
    $output .= maybe emit_x509_Extension("basicConstraints");
    $output .= maybe emit_x509_Extension("");
    $output .= maybe emit_x509_Extension("");
    $output .= maybe emit_x509_Extension("");
    $output .= maybe emit_x509_Extension("");

    return emit_asn1_cons($CONT, 3, emit_asn1_cons($UNIV, $SEQUENCE, $output));
}

###############################################################################
#
# Generate an X.509 certificate
#
###############################################################################
sub emit_x509_Time()
{
    # UTCTime or GeneralizedTime
    if (int(rand(2)) == 0) {
	return emit_asn1_utctime($UNIV, $UTCTime);
    } else {
	return emit_asn1_gentime($UNIV, $GeneralizedTime);
    }
}

sub emit_x509_Validity()
{
    my $output;
    $output  = emit_x509_Time();			# notBefore
    $output .= emit_x509_Time();			# notAfter
    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_AlgorithmIdentifier($)
{
    my ($oid) = @_;
    my $output;
 
    #$output  = emit_asn1_prim($UNIV, $OBJ_ID);		# algorithm
    $output  = emit_asn1_OID($UNIV, $OBJ_ID, $oid); # algorithm
    $output .= emit_asn1_prim($UNIV, $NULL);		# parameters
    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_Version()
{
    my $output = emit_asn1_prim($UNIV, $INTEGER, 0, 3);
    return emit_asn1_cons($CONT, 0, $output);
}

sub emit_x509_SubjectPublicKeyInfo()
{
    my $output;
    $output  = emit_x509_AlgorithmIdentifier("rsaEncryption");	# algorithm
    $output .= emit_asn1_prim($UNIV, $BIT_STRING);	# subjectPublicKey
    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_TBSCertificate()
{
    my $output;

    $output  = emit_x509_Version;			# version
    $output .= emit_asn1_prim($UNIV, $INTEGER);		# serialNumber
    $output .= emit_x509_AlgorithmIdentifier("sha1WithRSAEncryption");	# signature
    $output .= emit_x509_Name();			# issuer
    $output .= emit_x509_Validity();			# validity
    $output .= emit_x509_Name();			# subject
    $output .= emit_x509_SubjectPublicKeyInfo();	# subjectPublicKeyInfo
    $output .= maybe emit_asn1_prim($CONT, 1);		# issuerUniqueID
    $output .= maybe emit_asn1_prim($CONT, 2);		# subjectUniqueID
    $output .= emit_x509_Extensions();			# extensions

    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

sub emit_x509_Certificate()
{
    my $output;

    $output  = emit_x509_TBSCertificate();		# tbsCertificate
    $output .= emit_x509_AlgorithmIdentifier("sha1WithRSAEncryption");	# signatureAlgorithm
    $output .= emit_asn1_prim($UNIV, $BIT_STRING);	# signature

    return emit_asn1_cons($UNIV, $SEQUENCE, $output);
}

print emit_x509_Certificate();
