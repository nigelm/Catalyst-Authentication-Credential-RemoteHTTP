use strict;
use warnings;

use Test::More;

BEGIN {
    plan skip_all => "HTTP::Server::Simple is required for this test"
      unless eval { require HTTP::Server::Simple };
    plan skip_all =>
      "Catalyst::Authentication::Store::Minimal is required for this test"
      unless eval { require Catalyst::Authentication::Store::Minimal };
    plan "no_plan";
}

use lib 't/lib';
use TestWebServer;
use Catalyst::Test qw/AuthTestApp/;

# this test should be run *without* the authenticating server
ok( get("/testnotworking"), "get ok" );

my $pid = TestWebServer->new(8080)->background;
ok( $pid, 'Start authenticating web server' );
sleep(1);# give it time to start

# this test should be run *with* the authenticating server
ok( get("/testworking"), "get ok" );

# and kill off the test web server
kill 9, $pid;
