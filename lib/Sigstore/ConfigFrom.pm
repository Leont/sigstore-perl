package Sigstore::ConfigFrom;

use 5.020;
use warnings;
use experimental qw/signatures/;

use Carp;

sub trusted_root($self) {
	return $self->{trusted_root} //= do {
		my $path = $self->trusted_root_path or croak "Could not find path for trusted root";
		require Sigstore::TrustedRoot;
		Sigstore::TrustedRoot->load_file($path);
	}
}

sub signing_config($self, %options) {
	my $path = $self->signing_config_path or croak "Could not find path for signer configuration";
	require Sigstore::Signer;
	return Sigstore::Signer->load_file($path, %options);
}

1;

# ABSTRACT: A baseclass for configuration providers

=head1 SYNOPSIS

 my $trusted_root = $roots->trusted_root(%options);

=head1 DESCRIPTION

This is a baseclass for configuration providers. It should never be instantiated directly.

=method trusted_root

 my $trusted_root = $roots->trusted_root;

This returns a L<Sigstore::TrustedRoot|Sigstore::TrustedRoot>.

=method trusted_root_path

 my $path = $roots->trusted_root_path;

This returns the path to the trusted root file.

=method signing_config

 my $signer = $roots->signing_config(%options);

This returns a L<Sigstore::Signer|Sigstore::Signer>. It takes the same arguments are L<Sigstore::Signer->new|Sigstore::Signer/new>.

=method signing_config_path

 my $path = $roots->signing_config_path;

This returns the path to the signing config file.

=head1 SEE ALSO

=over 4

=item * L<Sigstore::ConfigFrom::ShareDir|Sigstore::ConfigFrom::ShareDir>

=back
