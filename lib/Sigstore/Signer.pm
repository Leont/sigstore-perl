package Sigstore::Signer;

use 5.020;
use warnings;
use experimental qw/signatures postderef lexical_subs/;

use Crypt::OpenSSL3;
use Sigstore::Util qw/digest dsse_pae parse_time read_binary $sha256/;

use Carp 'croak';
use HTTP::Tiny;
use MIME::Base64;
use JSON::PP;
use Time::Piece;
our @CARP_NOT = 'Sigstore::ConfigFrom';

sub load_file($class, $filename, %options) {
	my $content = read_binary($filename);
	my $json = decode_json($content) or croak "Could not decode $filename";
	return $class->load($json, %options);
}

my sub filter_entries($entries, $time, $api_version) {
	for my $entry ($entries->@*) {
		next if defined $api_version && $api_version != $entry->{majorApiVersion};
		next if parse_time($entry->{validFor}{start}) > $time;
		next if $entry->{validFor}{end} and parse_time($entry->{validFor}{end}) < $time;
		return $entry->{url} => $entry->{majorApiVersion};
	}
	return ();
}

for my $name (qw/oidc ca tsa tlog/) {
	my $sub = sub ($self) { return $self->{$name} };
	no strict 'refs';
	*{"${name}_url"} = $sub;
}

sub load($class, $json, %options) {
	my $time = delete $options{time} // time;
	my $rekor = delete $options{rekor};

	my ($oidc) = filter_entries($json->{oidcUrls}, $time, 1) or croak 'Could not find oidc url';
	my ($ca) = filter_entries($json->{caUrls}, $time, 1) or croak 'Could not find CA url';
	my ($tsa) = filter_entries($json->{tsaUrls}, $time, 1) or croak 'Could not find TSA url';
	my ($tlog, $version) = filter_entries($json->{rekorTlogUrls}, $time, $rekor) or croak 'Could not find tlog url';
	$rekor //= $version;

	return bless {
		oidc  => $oidc,
		ca    => $ca,
		tsa   => $tsa,
		tlog  => $tlog,
		rekor => $rekor,
		http  => HTTP::Tiny->new,
	}, $class;
}

my sub generate_key() {
	my $generator = Crypt::OpenSSL3::PKey::Context->new_from_name('EC') or croak 'Could not generate key';
	$generator->keygen_init  or croak 'Could not generate key';
	$generator->set_params({ group => 'prime256v1' }) or croak 'Could not generate key';
	my $key = $generator->generate or croak 'Could not generate key';
	return $key;
}

my sub generate_signature($key, $digest) {
	my $signing = Crypt::OpenSSL3::PKey::Context->new($key);
	$signing->sign_init or croak 'Could not create signature';
	my $signature = $signing->sign($digest) or croak 'Could not create signature';
	return $signature;
}

sub _get_certificate($self, $key, $token) {
	my $csr = Crypt::OpenSSL3::X509::Request->new;
	$csr->set_pubkey($key) or croak 'Could not create certificate request';
	$csr->sign($key, $sha256) or croak 'Could not create certificate request';
	my $csr_bio = Crypt::OpenSSL3::BIO->new_mem;
	$csr->write_pem($csr_bio);
	my $csr_pem = $csr_bio->read($csr_bio->pending);
	my %signing_payload = (
		credentials               => { oidcIdentityToken => $token },
		certificateSigningRequest => encode_base64($csr_pem, ''),
	);
	my $signing_payload = encode_json(\%signing_payload);

	my $certificate_url = "$self->{ca}/api/v2/signingCert";
	my $cert_response = $self->{http}->post($certificate_url, {
		headers => { 'content-type' => 'application/json' },
		content => $signing_payload,
	});
	croak "Could not get certificate: $cert_response->{content}" if $cert_response->{status} != 200;
	my $cert_content = decode_json($cert_response->{content});

	my @certificates;
	for my $pem ($cert_content->{signedCertificateEmbeddedSct}{chain}{certificates}->@*) {
		my $bio = Crypt::OpenSSL3::BIO->new_mem;
		$bio->write($pem);
		push @certificates, Crypt::OpenSSL3::X509->read_pem($bio);
	}
	return @certificates;
}

sub _get_timestamp($self, $signature) {
	my $algo = Crypt::OpenSSL3::X509::Algorithm->new;
	$algo->set_md($sha256);
	my $tsp_imprint = Crypt::OpenSSL3::Timestamp::Imprint->new;
	$tsp_imprint->set_algo($algo);
	$tsp_imprint->set_msg(digest($sha256, $signature));
	my $tsp_request = Crypt::OpenSSL3::Timestamp::Request->new;
	$tsp_request->set_msg_imprint($tsp_imprint);

	my $tsp_response = $self->{http}->post($self->{tsa}, {
		headers => { 'content-type' => 'application/timestamp-query' },
		content => $tsp_request->encode_der,
	});
	croak "Could not get timestamp response: $tsp_response->{content}" if $tsp_response->{status} != 200;
	return $tsp_response->{content};
}

my sub rewrite($input) {
	return encode_base64(pack('H*', $input), '')
}

sub _get_transparency_log_v1($self, $digest, $signature, $rekord, $certificate) {

	my $payload = encode_json($rekord);

	my $rekor_url = $self->{tlog};
	my $rekor_response = $self->{http}->post("$rekor_url/api/v1/log/entries", {
		headers => { 'content-type' => 'application/json' },
		content => $payload,
	});
	croak "Could not get transparency entry: $rekor_response->{content}" if $rekor_response->{status} != 201;
	my $rekor_upper_entry = decode_json($rekor_response->{content});
	my ($rekor_entry) = values $rekor_upper_entry->%*;

	return {
		kindVersion      => {
			kind    => $rekord->{kind},
			version => $rekord->{apiversion},
		},
		logIndex          => "$rekor_entry->{logIndex}",
		logId             => { keyId => rewrite($rekor_entry->{logID}) },
		integratedTime    => "$rekor_entry->{integratedTime}",
		inclusionPromise  => { signedEntryTimestamp => $rekor_entry->{verification}{signedEntryTimestamp} },
		inclusionProof    => {
			logIndex   => "$rekor_entry->{verification}{inclusionProof}{logIndex}",
			rootHash   => rewrite($rekor_entry->{verification}{inclusionProof}{rootHash}),
			hashes     => [ map rewrite($_), $rekor_entry->{verification}{inclusionProof}{hashes}->@* ],
			treeSize   => "$rekor_entry->{verification}{inclusionProof}{treeSize}",
			checkpoint => { envelope => $rekor_entry->{verification}{inclusionProof}{checkpoint} }
		},
		canonicalizedBody => $rekor_entry->{body},
	};
}

sub _get_transparency_log_v2($self, $digest, $signature, $certificate) {
	my %rekord = (
		hashedRekordRequestV002 => {
			signature => {
				content => encode_base64($signature, ''),
				verifier => {
					x509Certificate => {
						rawBytes => encode_base64($certificate->encode_der, ''),
					},
					keyDetails => 'PKIX_ECDSA_P256_SHA_256',
				},
			},
			digest => encode_base64($digest, ''),
		},
	);
	my $payload = encode_json(\%rekord);

	my $rekor_url = $self->{tlog};
	my $rekor_response = $self->{http}->post("$rekor_url/api/v2/log/entries", {
		headers => { 'content-type' => 'application/json' },
		content => $payload,
	});
	croak "Could not get transparency entry: $rekor_response->{content}" if $rekor_response->{status} != 201;
	return decode_json($rekor_response->{content});
}

my sub make_bundle($digest, $signature, $certificate, $timestamp, $rekor_entry) {
	return (
		mediaType => 'application/vnd.dev.sigstore.bundle.v0.3+json',
		verificationMaterial => {
			certificate => { rawBytes => encode_base64($certificate->encode_der, '') },
			tlogEntries => [ $rekor_entry ],
			timestampVerificationData => {
				rfc3161Timestamps => [ { signedTimestamp => encode_base64($timestamp, '')} ]
			},
		}
	);
}

my sub serialize_cert($certificate) {
	my $bio_cert = Crypt::OpenSSL3::BIO->new_mem;
	$certificate->write_pem($bio_cert);
	return encode_base64($bio_cert->read($bio_cert->pending), '');
}

sub sign($self, $content, $token) {
	my $key = generate_key();
	my $digest = digest($sha256, $content);
	my $signature = generate_signature($key, $digest);
	my ($certificate) = $self->_get_certificate($key, $token);
	my $timestamp = $self->_get_timestamp($signature);

	my $rekor_response;
	if ($self->{rekor} == 1) {
		my %rekord = (
			kind => 'hashedrekord',
			apiversion => '0.0.1',
			spec => {
				data => {
					hash => {
						algorithm => 'sha256',
						value     => unpack('H*', $digest),
					},
				},
				signature => {
					content   => encode_base64($signature, ''),
					publicKey => { content => serialize_cert($certificate) },
				},
			},
		);
		$rekor_response = $self->_get_transparency_log_v1($digest, $signature, \%rekord, $certificate);
	} elsif ($self->{rekor} == 2) {
		$rekor_response = $self->_get_transparency_log_v2($digest, $signature, $certificate);
	}

	my %bundle = make_bundle($digest, $signature, $certificate, $timestamp, $rekor_response);
	$bundle{messageSignature} = {
		messageDigest => {
			algorithm => 'SHA2_256',
			digest    => encode_base64($digest, ''),
		},
		signature => encode_base64($signature, ''),
	};

	return \%bundle;
}

sub sign_file($self, $artifact, $token) {
	my $artifact_content = read_binary($artifact);
	return $self->sign($artifact_content, $token);
}

my $intoto_type = 'application/vnd.in-toto+json';

sub attest($self, $content, $filename, $token) {
	my $key = generate_key();

	my $tbs = dsse_pae($intoto_type, $content);
	my $digest = digest($sha256, $tbs);
	my $signature = generate_signature($key, $digest);
	my ($certificate) = $self->_get_certificate($key, $token);
	my $timestamp = $self->_get_timestamp($signature);

	my %envelope = (
		payload     => encode_base64($content, ''),
		payloadType => $intoto_type,
		signatures  => [
			{ sig => encode_base64($signature, '') }
		],
	);
	my $envelope = JSON::PP->new->canonical->encode(\%envelope);

	my $rekor_response;
	if ($self->{rekor} == 1) {
		my %rekord = (
			kind => 'dsse',
			apiversion => '0.0.1',
			spec => {
				data => { hash => { value => unpack 'H*', $digest } },
				proposedContent => {
					envelope  => $envelope,
					verifiers => [ serialize_cert($certificate) ],
				}
			},
		);
		$rekor_response = $self->_get_transparency_log_v1($digest, $signature, \%rekord, $certificate);
	} elsif ($self->{rekor} == 2) {
		$rekor_response = $self->_get_transparency_log_v2($digest, $signature, $certificate);
	}

	my %bundle = make_bundle($digest, $signature, $certificate, $timestamp, $rekor_response);
	$bundle{dsseEnvelope} = \%envelope;
	return \%bundle;
}

sub attest_file($self, $filename, $token) {
	my $artifact_content = read_binary($filename);
	return $self->attest($artifact_content, $filename, $token);
}

1;

# ABSTRACT: A Sigstore Signer

=head1 SYNOPSIS

 my $config = Sigstore::ConfigFrom::SharedDir->new(mode => 'production');
 my $signer = $config->signing_config;
 my $bundle_data = $signer->sign_file($token_response->{content}, $artifact);
 my $bundle = Sigstore::Bundle->load($bundle_data);
 $bundle->verify_file($artifact, $config->trusted_root);
 write_file($bundle_name, encode_json($bundle_data));

=head2 DESCRIPTION

This is a object for sigstore signing. It needs a configuration that covers each of its four steps (getting the OIDC token, getting a certificate, getting a timestamp and getting a transaction log).

=method load

 my $signer = Sigstore::Signer->load($config_data, %options);

This loads a signing configuration from C<$config_data>. It currently takes one named option:

=over 4

=item * rekor

The rekor version to be used. This currently defaults to C<1>, but may change in the future.

=back

=method load_file

 my $singer = Sigstore::Signer->load_file($config_file, %options);

This loads a JSON encoded signing configuration from C<$config_file>. It takes the same options as C<load>.

=method sign

 my $bundle_data = $signer->sign($artifact_data, $token);

 This uses JWT C<$token> to create a signature over C<$artifact_data>, and returns it as a message-digest type bundle hash that should be encoded as a JSON file.

=method sign_file

 my $bundle_data = $signer->sign_file($artifact_file, $token);

This uses JWT C<$token> to create a signature over C<$artifact_file>, and returns it as a message-digest type bundle hash that should be encoded as a JSON file.

=method attest

 my $bundle_data = $singer->attest($artifact_data, $artifact_name, $token);

This uses JWT C<$token> to create a signature over C<$_data>, and returns it as a DSSE type bundle hash that should be encoded as a JSON file.

=method attest_file

 my $bundle_data = $signer->attest_file($intoto_file, $token);

This uses JWT C<$token> to create a signature over C<$intoto_data>, and returns it as a DSSE type bundle hash that should be encoded as a JSON file.

=method oidc_url

 my $url = $signer->oidc_url;

This returns the base-URL for the OpenID Connect endpoints, this is needed to fetch the token used in signing.

=begin Pod::Coverage

ca_url
tlog_url
tsa_url

=end Pod::Coverage
