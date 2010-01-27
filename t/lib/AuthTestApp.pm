package AuthTestApp;
use warnings;
use strict;

use Catalyst qw/
  Authentication
  /;

use Test::More;
use Test::Exception;

# this info needs to match that in TestWebServer
our $members = {
    insecure => { password => '123456' },
    paranoid => { password => 'very_secure_password!' }
};

sub testnotworking : Local {
    my ( $self, $c ) = @_;

    ok( !$c->user, "no user" );
    while ( my ( $user, $info ) = each %$members ) {
        ok(
            !$c->authenticate(
                { username => $user, password => $info->{password} }, 'members'
            ),
            "user $user authentication"
        );
        ok(
            !$c->authenticate(
                { username => $user, password => 'wrong password' }, 'members'
            ),
            "user $user authentication - wrong password"
        );
    }
    $c->res->body("ok");
}

sub testworking : Local {
    my ( $self, $c ) = @_;

    ok( !$c->user, "no user" );
    while ( my ( $user, $info ) = each %$members ) {
        ok(
            $c->authenticate(
                { username => $user, password => $info->{password} }, 'members'
            ),
            "user $user authentication"
        );
        ok(
            !$c->authenticate(
                { username => $user, password => 'wrong password' }, 'members'
            ),
            "user $user authentication - wrong password"
        );

        $c->logout;

        # sanity check
        ok( !$c->user, "no more user after logout" );

    }
    $c->res->body("ok");
}

__PACKAGE__->config->{'Plugin::Authentication'} = {
    default_realm => 'members',
    realms        => {
        members => {
            credential => {
                class => 'RemoteHTTP',
                url   => 'http://127.0.0.1:8080/stuff.html',
            },
            store => {
                class => 'Minimal',
                users => $members
            }
        },
    }
};

__PACKAGE__->setup;
