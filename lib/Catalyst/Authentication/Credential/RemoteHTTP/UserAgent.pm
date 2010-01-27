package Catalyst::Authentication::Credential::RemoteHTTP::UserAgent;
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

=head1 NAME

Catalyst::Authentication::Credential::RemoteHTTP::UserAgent - Wrapper for LWP::UserAgent

=head1 DESCRIPTION

A thin wrapper for L<LWP::UserAgent> to make basic auth simpler.

=head1 METHODS

=head2 set_credentials

now takes just a username and password

=head2 get_basic_credentials

Returns the set credentials, takes no options.

=head1 AUTHOR

Nigel Metheringham <nigelm@cpan.org> - integration into L<Catalyst::Authentication::Credential::RemoteHTTP>

Marcus Ramberg <mramberg@cpan.org - original code in L<Catalyst::Plugin::Authentication::Credential::HTTP::User>

=head1 LICENSE

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut

1;
