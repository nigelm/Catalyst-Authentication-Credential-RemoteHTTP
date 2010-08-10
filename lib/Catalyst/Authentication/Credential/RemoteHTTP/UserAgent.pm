package Catalyst::Authentication::Credential::RemoteHTTP::UserAgent;

# ABSTRACT: Wrapper for LWP::UserAgent

use strict;
use warnings;
use base qw/LWP::UserAgent/;

sub set_credentials {
    my ($self, $user, $pass) = @_;
    @{ $self->{credentials} } = ($user, $pass);
}

sub get_basic_credentials {
    my $self = shift;
    return @{ $self->{credentials} };
}

=head1 DESCRIPTION

A thin wrapper for L<LWP::UserAgent> to make basic auth simpler.

=head1 METHODS

=head2 set_credentials

now takes just a username and password

=head2 get_basic_credentials

Returns the set credentials, takes no options.

=head1 ACKNOWLEDGEMENTS

Marcus Ramberg <mramberg@cpan.org - original code in L<Catalyst::Plugin::Authentication::Credential::HTTP::User>

=cut

1;
