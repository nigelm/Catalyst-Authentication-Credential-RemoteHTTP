package AuthTestApp;
use warnings;
use strict;

use Catalyst qw/
  Authentication
  /;

# this info needs to match that in TestWebServer
our $members = {
    insecure => { password => '123456' },
    paranoid => { password => 'very_secure_password!' }
};

__PACKAGE__->config('Plugin::Authentication' => {
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
});

__PACKAGE__->setup;
