package Sigstore::TrustedRoot;

use 5.020;
use warnings;
use experimental qw/signatures postderef lexical_subs/;

use Crypt::OpenSSL3;
use Sigstore::Util qw/decode_cert digest parse_time read_binary %hash_for/;

use Carp;
use JSON::PP;
use File::Temp 'tempfile';
use MIME::Base64;
use Time::Piece;
our @CARP_NOT = 'Sigstore::ConfigFrom';

use constant {
	VFY_DATA               => Crypt::OpenSSL3::Timestamp::Verifier::VFY_DATA,
	VFY_SIGNATURE          => Crypt::OpenSSL3::Timestamp::Verifier::VFY_SIGNATURE,
	PUBLIC_KEY             => Crypt::OpenSSL3::PKey::PUBLIC_KEY,
	PURPOSE_CODE_SIGN      => Crypt::OpenSSL3::X509::VerifyParam->can('PURPOSE_CODE_SIGN') // Crypt::OpenSSL3::X509::VerifyParam::PURPOSE_ANY,
	PURPOSE_TIMESTAMP_SIGN => Crypt::OpenSSL3::X509::VerifyParam::PURPOSE_TIMESTAMP_SIGN,
};

sub load_file($class, $filename) {
	my $content = read_binary($filename);
	my $json = decode_json($content) or croak "Could not decode $filename";
	return $class->load($json);
}

my %hash_for_signer = (
	PKIX_RSA_PKCS1V15_2048_SHA256 => $hash_for{SHA2_256},
	PKIX_RSA_PKCS1V15_3072_SHA256 => $hash_for{SHA2_256},
	PKIX_RSA_PKCS1V15_4096_SHA256 => $hash_for{SHA2_256},
	PKIX_RSA_PSS_2048_SHA256 => $hash_for{SHA2_256},
	PKIX_RSA_PSS_3072_SHA256 => $hash_for{SHA2_256},
	PKIX_RSA_PSS_4096_SHA256 => $hash_for{SHA2_256},
	PKIX_ECDSA_P256_SHA_256 => $hash_for{SHA2_256},
	PKIX_ECDSA_P384_SHA_384 => $hash_for{SHA2_384},
	PKIX_ECDSA_P521_SHA_512 => $hash_for{SHA2_512},
	PKIX_ED25519            => undef,
);

my sub pkcs1_to_subject_publickey($input) {
	my $pkey_ref = Crypt::OpenSSL3::Decoder::Context::PKey->new;
	my $decoder = Crypt::OpenSSL3::Decoder::Context->new_for_pkey($pkey_ref, 'DER', 'pkcs1', 'RSA', PUBLIC_KEY);
	$decoder->from_data(decode_base64($input));
	return $input unless $pkey_ref->get_value;
	return encode_base64($pkey_ref->get_value->encode_der_public_key, '');
}

sub load($class, $json) {
	croak "Unknown trust root type $json->{mediaType}" unless $json->{mediaType} eq 'application/vnd.dev.sigstore.trustedroot+json;version=0.1';

	my $cert_store = Crypt::OpenSSL3::X509::Store->new;
	$cert_store->set_purpose(PURPOSE_CODE_SIGN);
	my %cert_by_id;
	for my $ca ($json->{certificateAuthorities}->@*) {
		for my $cert_raw ($ca->{certChain}{certificates}->@*) {
			my $ca_cert = decode_cert($cert_raw->{rawBytes});
			$cert_by_id{$ca_cert->get_subject_key_id} = $ca_cert;
			$cert_store->add_cert($ca_cert);
		}
	}

	my @stamp_items;
	for my $ca ($json->{timestampAuthorities}->@*) {
		my @certs = map { decode_cert($_->{rawBytes}) } $ca->{certChain}{certificates}->@*;
		my $start = parse_time($ca->{validFor}{start});
		my $end = $ca->{validFor}{end} ? parse_time($ca->{validFor}{end}) : undef;
		push @stamp_items, {
			certs => \@certs,
			start => $start,
			end   => $end,
		};
	}

	my $ctlog_store = Crypt::OpenSSL3::X509::Transparency::Log::Store->new;
	my $ctlog_format = "enabled_logs=log%d\n\n[log%d]\ndescription = %s\nkey = %s\n";
	my $ctlog_entry = 0;
	for my $ctlog ($json->{ctlogs}->@*) {
		my $key = $ctlog->{publicKey}{rawBytes};
		$key = pkcs1_to_subject_publickey($key) if $ctlog->{publicKey}{keyDetails} =~ /^PKCS1_/;

		if ($ctlog_store->can('add_log_base64')) { # OpenSSL 4.1
			$ctlog_store->add_log_base64($key, $ctlog->{baseUrl});
		} else {
			my ($handle, $filename) = tempfile(UNLINK => 1);
			printf $handle $ctlog_format, ($ctlog_entry) x 2, $ctlog->{baseUrl}, $key;
			close $handle;
			$ctlog_store->load_file($filename) or croak "Could not add log$ctlog_entry";
			$ctlog_entry++;
		}
	}

	my %tlog_key_for;
	for my $tctlog ($json->{tlogs}->@*) {
		my $der = decode_base64($tctlog->{publicKey}{rawBytes});
		my $key = Crypt::OpenSSL3::PKey->decode_der_public_key($der) or next;
		my $hash_details = $tctlog->{hashAlgorithm} or next;
		my $hash = $hash_for{$hash_details} or next;
		my $sign_details = $tctlog->{publicKey}{keyDetails} or next;
		my $md = $hash_for_signer{$sign_details};
		my $id = $tctlog->{logId}{keyId} or next;
		$tlog_key_for{decode_base64($id)} = [ $key, $hash, $md ];
	}

	return bless {
		cert_store  => $cert_store,
		cert_by_id  => \%cert_by_id,
		stamp_items => \@stamp_items,
		ctlog_store => $ctlog_store,
		tlog_keys   => \%tlog_key_for,
	}, $class;
}

sub verify_timestamp($self, $signature, $timestamp_der) {
	my $signed_timestamp = Crypt::OpenSSL3::Timestamp::Response->decode_der($timestamp_der);
	my $timestamp = $signed_timestamp->get_tst_info->get_time;

	my $stamp_store = Crypt::OpenSSL3::X509::Store->new;
	$stamp_store->set_purpose(PURPOSE_TIMESTAMP_SIGN) or croak "Can't set purpose to timestamp store";
	$stamp_store->get_param->set_time($timestamp);
	my @stamp_certs;
	for my $item ($self->{stamp_items}->@*) {
		next if $timestamp < $item->{start};
		next if defined $item->{end} && $timestamp > $item->{end};
		my @certs = $item->{certs}->@*;
		$stamp_store->add_cert(pop @certs) or croak "Can't add certificate to timestamp store";
		push @stamp_certs, @certs;
	}

	my $verifier = Crypt::OpenSSL3::Timestamp::Verifier->new;
	$verifier->set_store($stamp_store) or croak "Couldn't set timestamp certificate store";
	$verifier->set_certs(\@stamp_certs) or croak "Coudln't set timestamp untrusted certificates";
	my $in = Crypt::OpenSSL3::BIO->new_mem;
	$in->write($signature);
	$verifier->set_data($in) or croak "Couldn't set timestamp data";
	$verifier->set_flags(VFY_DATA | VFY_SIGNATURE) or croak 'Could not set timestamp flags';

	my $verified = $verifier->verify_response($signed_timestamp);
	return $verified ? $timestamp : undef;
}

sub verify_certificate($self, $certificate, $timestamp, $untrusted = undef) {
	my $cert_context = Crypt::OpenSSL3::X509::Store::Context->new;
	$cert_context->init($self->{cert_store}, $certificate);
	$cert_context->set_untrusted($untrusted) if $untrusted;
	$cert_context->set_time($timestamp);
	return $cert_context->verify;
}

sub verify_sct($self, $cert, $sct, $time = time + 300) {
	my $issuer_cert = $self->{cert_by_id}{$cert->get_authority_key_id} or return undef;
	my $ct_evaluator = Crypt::OpenSSL3::X509::Transparency::Evaluator->new;
	$ct_evaluator->set_log_store($self->{ctlog_store});
	$ct_evaluator->set_cert($cert);
	$ct_evaluator->set_time($time * 1000);
	$ct_evaluator->set_issuer($issuer_cert);
	return $sct->validate($ct_evaluator) ? $sct->get_timestamp / 1000 : undef;
}

my sub node_hash($digest, $left, $right) {
	return digest($digest, "\x01" . $left . $right);
}

my sub verify_inclusion($digest, $leaf_hash, $leaf_index, $tree_size, $proof, $expected_root) {
	use integer;
	return unless 0 <= $leaf_index < $tree_size;
	my ($fn, $sn) = ($leaf_index, $tree_size - 1);
	my $h = $leaf_hash;
	for my $p ($proof->@*) {
		return if $sn == 0;
		if ($fn % 2 or $fn == $sn) {
			$h = node_hash($digest, $p, $h);
			while ($fn != 0 and not $fn % 2) {
				$fn /= 2;
				$sn /= 2;
			}
		} else {
			$h = node_hash($digest, $h, $p);
		}
		$fn /= 2;
		$sn /= 2;
	}
	return $sn == 0 && $h eq $expected_root;
}

sub verify_tlog($self, $log_id, $proof, $body) {
	my $log_ref = $self->{tlog_keys}{$log_id} or return undef;
	my ($key, $digest, $md) = $log_ref->@* or return undef;
	return undef if not $proof or not $proof->{checkpoint} or not $proof->{checkpoint}{envelope};
	my ($signed, $signatures) = $proof->{checkpoint}{envelope} =~ / \A ( .*? \n ) \n (.*) /xms or return undef;

	my $prefix = substr $log_id, 0, 4;
	my $found = 0;
	for my $line ($signatures =~ / ^ (.+) $ /gmx) {
		my ($keyname, $b64) = $line =~ / \A \x{2014} \s+ (\S+) \s+ (\S+) /xms;
		my ($key_id, $signature) = unpack 'a4 a*', decode_base64($b64);
		next if $key_id ne $prefix;

		my $ctx = Crypt::OpenSSL3::MD::Context->new;
		next unless $ctx->verify_init($md, $key);
		$found++ and last if $ctx->verify($signature, $signed);
	};
	return undef if not $found;

	my ($origin, $treesize, $root_b64, @exts) = $signed =~ / ^ (.+) $ /gmx;
	my $root = decode_base64($root_b64);
	return undef if $treesize != $proof->{treeSize} or $root ne decode_base64($proof->{rootHash});

	my $leaf_hash = digest($digest, "\0$body");
	my @proofs = map { decode_base64($_) } $proof->{hashes}->@*;
	my $verified = verify_inclusion($digest, $leaf_hash, $proof->{logIndex}, $treesize, \@proofs, $root);
	return $verified ? decode_json($body) : undef;
}

sub verify_inclusion_promise($self, $promise, $body, $integrated_time, $log_id, $log_index) {
	my ($key, $digest, $md) = $self->{tlog_keys}{$log_id}->@* or return undef;
	my %payload = (
		body           => encode_base64($body, ''),
		integratedTime => int $integrated_time,
		logID          => unpack('H*', $log_id),
		logIndex       => int $log_index,
	);
	my $signed = JSON::PP->new->canonical->encode(\%payload);
	my $ctx = Crypt::OpenSSL3::MD::Context->new;
	return undef unless $ctx->verify_init($md, $key);
	return $ctx->verify($promise, $signed);
}

1;

# ABSTRACT: A Sigstore Trusted Root

=head1 SYNOPSIS

 my $trusted_root = Sigstore::TrustedRoot->load_file($trusted_root_file);
 $bundle->verify_file($artifact, $trusted_root);

=head1 DESCRIPTION

An instance of this class represents a Sigstore trusted root. This is needed to verify the authenticity of a bundle. One should generally not use this class directly.

=method load

 my $trusted_root = Sigstore::TrustedRoot->load($data);

This loads a trusted root from the hashref C<$data>.

=method load_file

 my $trusted_root = Sigstore::TrustedRoot->load_file($filename)

This reads a trusted root JSON file, and loads it into a new object.

=method verify_timestamp

 my $time = $trusted_root->verify_timestamp($payload, $rfc3161_timestamp);

This verifies if a C<$payload> has been correctly timestamped. If successful it returns the time of the timestamp, otherwise it returns undef.

=method verify_tlog

 my $success = $trusted_root->verify_tlog($log_id, $proof, $body);

This checks if the key referenced by $log_id has correctly signed the proof, and returns the decoded body if so and undef otherwise.

=method verify_inclusion_promise

 $trusted_root->verify_inclusion_promise($promise, $body, $integrated_time, $log_id, $log_index)

This verifies if the inclusion C<$promise> is a correct signature of C<$body>, C<$integrated_time>, C<$log_id> and C<$log_index>.

=method verify_certificate

 $trusted_root->verify_certificate($certificate, $timestamp)

This verifies if a certificate was valid at time C<$timestamp> according to the CA trust anchors.

=method verify_sct

 $trusted_root->verify_sct($certificate, $sct)

This checks if the signed certificate timestamp was correct for the given C<$certificate>.

=begin Pod::Coverage

PUBLIC_KEY
PURPOSE_CODE_SIGN
PURPOSE_TIMESTAMP_SIGN
VFY_DATA
VFY_SIGNATURE

=end Pod::Coverage
