package Sigstore::Util;

use 5.020;
use warnings;
use experimental qw/signatures postderef lexical_subs/;

use Exporter 'import';
our @EXPORT_OK = qw/dsse_pae digest decode_cert read_binary %hash_for $sha256/;

use Crypt::OpenSSL3;
use Encode 'encode_utf8';
use File::Slurper 'read_binary';
use MIME::Base64 'decode_base64';

our %hash_for = map { $_ => Crypt::OpenSSL3::MD->fetch(tr/_/-/r) } qw/SHA2_256 SHA2_384 SHA2_512/;
our $sha256 = $hash_for{SHA2_256};

sub decode_cert($certificate_raw) {
	return Crypt::OpenSSL3::X509->decode_der(decode_base64($certificate_raw));
}

sub digest($md, $input) {
	my $md_context = Crypt::OpenSSL3::MD::Context->new;
	$md_context->init($md);
	$md_context->update($input);
	return $md_context->final;
}

sub dsse_pae($type, $payload) {
	$type = encode_utf8($type);
	return join ' ', 'DSSEv1', length $type, $type, length $payload, $payload;
}

1;
