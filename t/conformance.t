#! perl

use strict;
use warnings;

use Test::More;
BEGIN { binmode STDERR, ':utf8' }

use Sigstore::Bundle;
use Sigstore::TrustedRoot;

use File::Spec::Functions qw/catdir catfile/;

my $default_artifact = catfile('conformance', 'a.txt');
my $default_trusted_root_file = catfile('conformance', 'trusted_root.json');

opendir my $dh, 'conformance' or die;
for my $casename (sort grep !/^\./, readdir $dh) {
	my $casedir = catdir('conformance', $casename);
	next unless -d $casedir;
	my $bundle_file = catfile($casedir, 'bundle.sigstore.json');

	SKIP:
	{
		skip "$casename: intoto entries not implemented", 1 if $casename =~ /^intoto/;

		my $case_artifact = catfile($casedir, 'artifact');
		my $artifact = -e $case_artifact ? $case_artifact : $default_artifact;
		my $case_trusted_root = catfile($casedir, 'trusted_root.json');
		my $trusted_root_file = -e $case_trusted_root ? $case_trusted_root : $default_trusted_root_file;

		my $result = eval {
			my %options;
			my $keyfile = catfile($casedir, 'key.pub');
			if (-e $keyfile) {
				my $bio = Crypt::OpenSSL3::BIO->new_file($keyfile, 'r') or die;
				my $pkey = Crypt::OpenSSL3::PKey->read_pem_public_key($bio) or die "Could not open keyfile";
				$options{public_key} = $pkey;
			}

			my $bundle = Sigstore::Bundle->load_file($bundle_file);
			my $trusted_root = Sigstore::TrustedRoot->load_file($trusted_root_file) or die;
			my $metadata = $bundle->verify_file($artifact, $trusted_root, %options);
			if (!$options{public_key}) {
				die "Wrong issuer: $metadata->{issuer}" if $metadata->{issuer} ne 'https://token.actions.githubusercontent.com';
			}
			$metadata;
		};

		if ($casename !~ /_fail$/) {
			ok $result, $casename or diag $@;
		} else {
			ok !$result, $casename;
		}
	}
}

done_testing;
