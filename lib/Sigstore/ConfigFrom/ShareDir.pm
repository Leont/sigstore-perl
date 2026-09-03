package Sigstore::ConfigFrom::ShareDir;

use 5.020;
use warnings;
use experimental qw/signatures lexical_subs/;

use parent 'Sigstore::ConfigFrom';

use Carp;
use File::Spec::Functions qw/catdir catfile/;

sub _module_dir($module) {
	my $module_pathname = $module =~ s/::/-/gr;

	for my $candidate (@INC) {
		next if ref $candidate;
		my $dir = catdir($candidate, 'auto', 'share', 'module', $module_pathname);
		return $dir if -d $dir;
	}

	croak("Failed to find shared module dir for module '$module'");
}

my $module_dir = _module_dir(__PACKAGE__);

sub new($class, %options) {
	my $mode = $options{mode} // 'production';
	croak "unknown mode $mode" if $mode ne 'production' && $mode ne 'staging';
	return bless { mode => $mode }, $class;
}

sub trusted_root_path($self) {
	my $path = catfile($module_dir, $self->{mode}, 'trusted_root.json');
	croak "\u$self->{mode} trusted root is missing" unless -e $path;
	return $path;
}

sub signing_config_path($self) {
	my $path = catfile($module_dir, $self->{mode}, 'signing_config.v0.2.json');
	croak "\u$self->{mode} signing config is missing" unless -e $path;
	return $path;
}

1;

# ABSTRACT: Get Sigstore trusted root from a sharedir.

=head1 SYNOPSIS

 my $roots = Sigstore::ConfigFrom::ShareDir->new(mode => 'production');
 my $trusted_root = $roots->trusted_root(%options);

=head1 DESCRIPTION

This class provides canned versions of the Sigstore trusted roots. This is suitable for offline usage.

On top of the methods defined in its base-class L<Sigstore::ConfigFrom|Sigstore::ConfigFrom> it defines a single method: the constructor C<new>.

=method new

 Sigstore::ConfigFrom::ShareDir->new(%options);

=over 4

=item * mode

This selects the version of the trusted roots; allowed values are C<production> (the default) and C<staging>.

=back
