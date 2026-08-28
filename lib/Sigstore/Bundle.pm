package Sigstore::Bundle;

use 5.020;
use warnings;
use experimental qw/signatures postderef lexical_subs/;

use Crypt::OpenSSL3;
use Sigstore::Util qw/dsse_pae decode_cert digest read_binary %hash_for $sha256/;

use Carp 'croak';
use JSON::PP 'decode_json';
use MIME::Base64 'decode_base64';

sub load_file($class, $filename) {
	my $content = read_binary($filename);
	my $json = decode_json($content) or croak "Could not decode $filename";
	return $class->load($json);
}

my %oids = (
	8  => 'Issuer',
	9  => 'Build Signer URI',
	10 => 'Build Signer Digest',
	11 => 'Runner Environment',
	12 => 'Source Repository URI',
	13 => 'Source Repository Digest',
	14 => 'Source Repository Ref',
	15 => 'Source Repository Identifier',
	16 => 'Source Repository Owner URI',
	17 => 'Source Repository Owner Identifier',
	18 => 'Build Config URI',
	19 => 'Build Config Digest',
	20 => 'Build Trigger',
	21 => 'Run Invocation URI',
	22 => 'Source Repository Visibility At Signing',
	23 => 'Deployment Environment',
	24 => 'Token Subject',
);

my @nids = map { Crypt::OpenSSL3::NID->create("1.3.6.1.4.1.57264.1.$_", lc $oids{$_} =~ tr/ /_/r, "Sigstore $oids{$_}") } keys %oids;
my $issuer_fallback = Crypt::OpenSSL3::NID->create('1.3.6.1.4.1.57264.1.1', 'Issuer V1', 'Issuer V1');

sub load($class, $bundle) {
	my %result;

	if ($bundle->{mediaType} eq 'application/vnd.dev.sigstore.bundle.v0.3+json') {
		$result{version} = 3;
	} elsif ($bundle->{mediaType} =~ m{\A\Qapplication/vnd.dev.sigstore.bundle+json;version=0.\E([123])}) {
		$result{version} = $1;
	} else {
		die "Unknown bundle type $bundle->{mediaType}";
	}

	if (my $message_signature = $bundle->{messageSignature}) {
		$result{message_signature} = {
			digest_algorithm => $message_signature->{messageDigest}{algorithm},
			digest           => decode_base64($message_signature->{messageDigest}{digest}),
			signature        => decode_base64($bundle->{messageSignature}{signature}),
		};
	} elsif (my $dsse = $bundle->{dsseEnvelope}) {
		my @signatures = map { decode_base64($_->{sig}) } $dsse->{signatures}->@*;
		my $envelope = JSON::PP->new->canonical->encode($dsse);
		$result{dsse} = {
			payload       => decode_base64($dsse->{payload}),
			payload_type  => $dsse->{payloadType},
			signatures    => \@signatures,
			envelope_hash => digest($sha256, $envelope),
		};
	} else {
		croak "Unknown format";
	}

	if (my $certificate_raw = $bundle->{verificationMaterial}{certificate}{rawBytes}) {
		$result{cert} = decode_cert($certificate_raw);
	} elsif (my $certificate_raw2 = $bundle->{verificationMaterial}{x509CertificateChain}{certificates}) {
		croak 'No certificates' unless $certificate_raw2->@*;
		my @certs = map { decode_cert($_->{rawBytes}) } $certificate_raw2->@*;
		$result{cert} = shift @certs or croak 'No certificates';
		$result{untrusted} = \@certs if $result{version} < 3;
	} elsif (my $public_key_hint = $bundle->{verificationMaterial}{publicKey}{hint}) {
		$result{key_hint} = decode_base64($public_key_hint);
	} else {
		die "No cert or key hint!";
	}

	for my $timestamp_entry ($bundle->{verificationMaterial}{timestampVerificationData}{rfc3161Timestamps}->@*) {
		push $result{signed_timestamps}->@*, decode_base64($timestamp_entry->{signedTimestamp});
	}

	my @tlogs;
	for my $tlog ($bundle->{verificationMaterial}{tlogEntries}->@*) {
		push $result{tlogs}->@*, {
			body    => decode_base64($tlog->{canonicalizedBody}),
			log_id  => decode_base64($tlog->{logId}{keyId}),
			proof   => $tlog->{inclusionProof},
			kind    => $tlog->{kindVersion}{kind},
			version => $tlog->{kindVersion}{version},
			promise => $tlog->{inclusionPromise},
			integrated_time => $tlog->{integratedTime},
			log_index       => $tlog->{logIndex},
		};
	}

	return bless \%result, $class;
}

sub verify_file($self, $target_file, $trusted_root, %options) {
	my $content = $options{digest} ? undef : read_binary($target_file);
	return $self->verify($content, $trusted_root, %options);
}

sub verify($self, $content, $trusted_root, %options) {
	my ($digest, $digest_algorithm, $signature);

	my $pubkey = $self->{cert} ? $self->{cert}->get_pubkey : $options{public_key} ? $options{public_key} : croak "No public key known";
	my $pk_ctx = Crypt::OpenSSL3::PKey::Context->new($pubkey);
	$pk_ctx->verify_init;

	if (my $message_signature = $self->{message_signature}) {
		$digest = $options{digest} // digest($hash_for{$message_signature->{digest_algorithm}}, $content);
		croak 'Inequal digest' unless $digest eq $message_signature->{digest};

		croak 'Incorrect signature' unless $pk_ctx->verify($message_signature->{signature}, $digest);
		$digest_algorithm = $message_signature->{digest_algorithm};
		$signature = $message_signature->{signature};
	} elsif(my $dsse = $self->{dsse}) {
		my $computed_hash = $options{digest} // digest($sha256, $content);
		croak "Unknown payload type" if $dsse->{payload_type} ne 'application/vnd.in-toto+json';
		my $decoded = decode_json($dsse->{payload});
		my $given_hash = pack 'H*', $decoded->{subject}[0]{digest}{sha256};
		croak 'Inequal digest' unless $computed_hash eq $given_hash;

		my $pae = dsse_pae($dsse->{payload_type}, $dsse->{payload});
		$digest = digest($sha256, $pae);
		croak 'Incorrect signature' unless $pk_ctx->verify($dsse->{signatures}[0], $digest);
		$digest_algorithm = 'SHA2_256';
		$signature = $dsse->{signatures}[0];
	}

	my @timestamps;
	for my $signed_timestamp (($self->{signed_timestamps} // [])->@*) {
		my $timestamp = $trusted_root->verify_timestamp($signature, $signed_timestamp) or croak 'Invalid timestamp';
		push @timestamps, $timestamp;
	}

	my $valid_logs = 0;
	for my $tlog ($self->{tlogs}->@*) {
		my $decoded = $trusted_root->verify_tlog($tlog->{log_id}, $tlog->{proof}, $tlog->{body});
		next unless $decoded;

		if ($tlog->{kind} eq 'hashedrekord') {
			if ($tlog->{version} eq '0.0.2') {
				next if decode_base64($decoded->{spec}{hashedRekordV002}{signature}{content}) ne $signature;
				next if decode_base64($decoded->{spec}{hashedRekordV002}{data}{digest}) ne $digest;
				next if $decoded->{spec}{hashedRekordV002}{data}{algorithm} ne $digest_algorithm;
				if (my $cert = $self->{cert}) {
					next if decode_base64($decoded->{spec}{hashedRekordV002}{signature}{verifier}{x509Certificate}{rawBytes}) ne $cert->encode_der;
				} elsif ($pubkey) {
					next if decode_base64($decoded->{spec}{hashedRekordV002}{signature}{verifier}{publicKey}{rawBytes}) ne $pubkey->encode_der;
				} else {
					next;
				}
			} elsif ($tlog->{version} eq '0.0.1') {
				next if decode_base64($decoded->{spec}{signature}{content}) ne $signature;
				next if pack('H*', $decoded->{spec}{data}{hash}{value}) ne $digest;
				my $bio = Crypt::OpenSSL3::BIO->new_mem;
				if (my $cert = $self->{cert}) {
					$cert->write_pem($bio);
					next if decode_base64($decoded->{spec}{signature}{publicKey}{content}) ne $bio->read($bio->pending);
				} elsif ($pubkey) {
					$pubkey->write_pem_public_key($bio);
					next if decode_base64($decoded->{spec}{signature}{publicKey}{content}) ne $bio->read($bio->pending);
				} else {
					next;
				}
			}
		} elsif ($tlog->{kind} eq 'dsse') {
			next if pack('H*', $decoded->{spec}{envelopeHash}{value}) ne $self->{dsse}{envelope_hash};
			next if pack('H*', $decoded->{spec}{payloadHash}{value}) ne digest($sha256, $self->{dsse}{payload});
			next if decode_base64($decoded->{spec}{signatures}[0]{signature}) ne $signature;
			my $bio = Crypt::OpenSSL3::BIO->new_mem;
			$self->{cert}->write_pem($bio);
			next if decode_base64($decoded->{spec}{signatures}[0]{verifier}) ne $bio->read($bio->pending);
		} elsif ($tlog->{kind} eq 'intoto') {
			if (my $cert = $self->{cert}) {
				next if decode_base64(decode_base64($decoded->{spec}{content}{envelope}{payload})) ne $self->{dsse}{payload};
				my $bio = Crypt::OpenSSL3::BIO->new_mem;
				my $left = decode_base64($decoded->{spec}{content}{envelope}{signatures}[0]{publicKey});
				$bio->write($left);
				my ($type, $headers, $payload) = Crypt::OpenSSL3::PEM::read($bio);
				next if $payload ne $cert->encode_der;
				next if decode_base64(decode_base64($decoded->{spec}{content}{envelope}{signatures}[0]{sig})) ne $signature;
				next if pack('H*', $decoded->{spec}{content}{payloadHash}{value}) ne digest($sha256, $self->{dsse}{payload});
			}
		}
		$valid_logs++;

		if (my $promise_raw = $tlog->{promise}) {
			my $promise = decode_base64($promise_raw->{signedEntryTimestamp});
			my @args = $tlog->@{'body', 'integrated_time', 'log_id', 'log_index'};
			push @timestamps, $tlog->{integrated_time} if $trusted_root->verify_inclusion_promise($promise, @args);
		}
	}

	croak 'No valid transparency log entry' if $valid_logs == 0 and not $options{skip_tlogs};

	if (my $cert = $self->{cert}) {
		my $verified = 0;
		my $timestamps = $self->{signed_timestamps} // [];
		croak "No timestamps found" if not @timestamps;
		for my $timestamp (@timestamps) {
			croak "Certificate validation failed" unless $trusted_root->verify_certificate($cert, $timestamp, $self->{untrusted});
		}

		if (not $options{skip_scts}) {
			my $trusted_sct = 0;
			for my $sct ($cert->get_ct_precert_scts) {
				$trusted_sct++ if $trusted_root->verify_sct($cert, $sct);
			}
			croak 'No SCT was trusted' unless $trusted_sct;
		}
	} elsif (not defined $self->{key_hint}) {
		croak 'No certificate or key hint';
	}

	return $self->metadata;
}

sub metadata($self) {
	my %result;

	if (my $cert = $self->{cert}) {
		for my $nid (@nids) {
			if (defined(my $idx = $cert->get_ext_by_NID($nid))) {
				my $ext = $cert->get_ext($idx);
				my $data = Crypt::OpenSSL3::ASN1::Value->decode_der($ext->get_data);
				next unless $data->get_type == Crypt::OpenSSL3::ASN1::UTF8STRING;
				$result{ $nid->get_short_name } = $data->get_value;
			}
		}

		if (!$result{issuer} and defined(my $idx = $cert->get_ext_by_NID($issuer_fallback))) {
			$result{issuer} = $cert->get_ext($idx)->get_data;
		}

		my @subjects = $cert->get_subject_alt_names;
		$result{identity} = $subjects[0]->to_string if @subjects == 1;
	}

	return \%result;
}

1;

# ABSTRACT: A Sigstore bundle

=head1 SYNOPSIS

 my $bundle = Sigstore::Bundle->load_file($bundle_file);
 my $trusted_root = Sigstore::TrustedRoot->load_file($trusted_root_file);
 $bundle->verify_file($artifact, $trusted_root);

=head2 DESCRIPTION

A Sigstore bundle is a format for cryptographic signatures and verification metadata. It is used to verify the source of an artifact (usually but not necessarily tarball or other build artifact).

=method load

 Sigstore::Bundle->load($bundle_data);

This loads a bundle from a hash.

=method load_file

This loads a bundle from a JSON encoded file.

=method metadata

This returns the metadata of the bundle. It can contain the following keys:

=over

=item subject

The identity of the subject, e.g. C<user@example.com>.

=item issuer

This contains the issuer of the OpenID Connect Token that was presented at the time the code signing certificate was requested to be created. This corresponds to the C<iss> claim for non-federated tokens.

This claim is the URI of the OIDC Identity Provider that digitally signed the identity token. For example: C<https://oidc-issuer.com>.

=item build_signer_uri

Reference to specific build instructions that are responsible for signing. SHOULD be fully qualified. MAY be the same as Build Config URI.

For example a reusable workflow ref in GitHub Actions or a Circle CI Orb name/version. For example: C<https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0>.

=item build_signer_digest

Immutable reference to the specific version of the build instructions that is responsible for signing. For example: C<abc123> git commit SHA.

=item runner_environment

Runner Environment specifying whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure. For example: C<[platform]-hosted> and C<self-hosted>.

=item C<source_repository_uri>

Source repository URL that the build was based on. SHOULD be fully qualified. For example: C<https://example.com/owner/repository>.

=item source_repository_digest

Immutable reference to a specific version of the source code that the build was based upon. For example: C<abc123> git commit SHA.

=item source_repository_ref

Source Repository Ref that the build run was based upon. For example: C<refs/head/main> git branch or tag.

=item source_repository_identifier

Immutable identifier for the source repository the workflow was based upon. MAY be empty if the Source Repository URI is immutable. For example: C<1234> if using a primary key.

=item source_repository_owner_uri

Source repository owner URL of the owner of the source repository that the build was based on. SHOULD be fully qualified. MAY be empty if there is no Source Repository Owner. For example: C<https://example.com/owner>

=item source_repository_owner_identifier

Immutable identifier for the owner of the source repository that the workflow was based upon. MAY be empty if there is no Source Repository Owner or Source Repository Owner URI is immutable. For example: C<5678> if using a primary key.

=item build_config_uri

Build Config URL to the top-level/initiating build instructions. SHOULD be fully qualified. For example: C<https://example.com/owner/repository/build-config.yml>.

=item build_config_digest

Immutable reference to the specific version of the top-level/initiating build instructions. For example: C<abc123> git commit SHA.

=item build_trigger

Event or action that initiated the build. For example: C<push>.

=item run_invocation_uri

Run Invocation URL to uniquely identify the build execution. SHOULD be fully qualified. For example: C<https://github.com/example/repository/actions/runs/1536140711/attempts/1>.

=item source_repository_visibility_at_signing

Source repository visibility at the time of signing the certificate. MAY be empty if there is no Source Repository Visibility information available. For example: C<private> or C<public>.

=item deployment_environment

Deployment target for a given job that maps to deployment protection rules. May be empty if no environment is defined. For example: C<production> or C<staging>.

=item token_subject

The raw C<sub> claim from the OIDC ID token that was presented at the time the code signing certificate was requested. This preserves the original token subject as-is, regardless of how the provider maps it to certificate SANs or other extensions. For example: C<repo:sigstore/fulcio:ref:refs/heads/main> for GitHub Actions, or C<project_path:mygroup/myproject:ref_type:branch:ref:main> for GitLab.

=back

=method verify

 $bundle->verify($contents, $trusted_root, %options);

This verifies if the bundle is correctly signed for the data in C<$contents>, and returns the metadata on succes (and croaks on failure). Note that you will still need to check if the metadata is what you expect it to be (in particular the C<subject> and C<issuer> key).

It takes the following named options:

=over 4

=item * C<public_key>

The public key to be used with managed keys.

=item * C<skip_scts>

This will skip the checking of signed certificate transparency logs.

=item * C<skip_tlogs>

This will skip checking the transaction logs.

=back

=method verify_file

 $bundle->verify($artifact_file, $trusted_root, %options);

This verifies an artifact file against the bundle.
