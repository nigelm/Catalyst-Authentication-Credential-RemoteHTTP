package Catalyst::Authentication::Credential::RemoteHTTP;
use base qw/Catalyst::Authentication::Credential::Password/;

use warnings;
use strict;
use Catalyst::Authentication::Credential::RemoteHTTP::UserAgent;

=head1 NAME

Catalyst::Authentication::Credential::RemoteHTTP - Authenticate against remote HTTP server

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    use Catalyst qw/
      Authentication
      /;

    package MyApp::Controller::Auth;

    sub login : Local {
        my ( $self, $c ) = @_;

        $c->authenticate( { username => $c->req->param('username'),
                            password => $c->req->param('password') });
    }

=head1 DESCRIPTION

This authentication credential checker takes authentication
information (most often a username) and a password, and attempts to
validate the username and password provided against a remote http
server - ie against another web server.

This is useful for environments where you want to have a single
source of authentication information, but are not able to
conveniently use a networked authentication mechanism such as LDAP.

=head1 CONFIGURATION

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 METHODS

=head2 check_password

=cut

sub check_password {
    my ( $self, $user, $authinfo ) = @_;

    # keep_alive is forced to 1 if we are doing NTLM otherwise as config
    my $keep_alive =
      ( lc( $self->_config->{type} || '' ) eq 'ntlm' )
      ? 1
      : $self->_config->{keep_alive} || 0;

    # add prefix/suffix to user data
	# we have to use $authinfo->{username} as the obvious $user->id may
	# be something like a db primary key
    my $auth_user = join( '',
        ( $self->_config->{user_prefix} || '' ),
        $authinfo->{username},
        ( $self->_config->{user_suffix} || '' ) );

    # get the password
    my $password = $authinfo->{ $self->_config->{'password_field'} };

    # and then the URL
    my $url = $self->_config->{url};

    my $ua =
      Catalyst::Authentication::Credential::RemoteHTTP::UserAgent->new(
        keep_alive => $keep_alive );
    my $req = HTTP::Request->new( HEAD => $url );

    # set the credentials for the request.
    $ua->credentials( $auth_user, $password );

    # do the request
    my $res = $ua->request($req);

    # did it succeed
    return $res->is_success;
}

=head1 AUTHOR

Nigel Metheringham, C<< <nigelm at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-catalyst-authentication-credential-remotehttp at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Catalyst-Authentication-Credential-RemoteHTTP>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Catalyst::Authentication::Credential::RemoteHTTP


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Catalyst-Authentication-Credential-RemoteHTTP>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Catalyst-Authentication-Credential-RemoteHTTP>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Catalyst-Authentication-Credential-RemoteHTTP>

=item * Search CPAN

L<http://search.cpan.org/dist/Catalyst-Authentication-Credential-RemoteHTTP/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2010 Nigel Metheringham.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of Catalyst::Authentication::Credential::RemoteHTTP
