use inc::Module::Install;

if ( $Module::Install::AUTHOR ) {
    system( 'pod2text lib/Catalyst/Authentication/Credential/RemoteHTTP.pm > README' )
        and die;
}

name     'Catalyst-Authentication-Credential-RemoteHTTP';
all_from 'lib/Catalyst/Authentication/Credential/RemoteHTTP.pm';
author   q{Nigel Metheringham <nigelm@cpan.org>};
license  'perl';

requires 'Catalyst';
requires 'Catalyst::Runtime';
requires 'Catalyst::Controller';
requires 'Catalyst::Exception';
requires 'LWP::UserAgent';
requires 'Moose';
requires 'MooseX::Types';
requires 'MooseX::Types::Moose';
requires 'namespace::autoclean';

test_requires 'Test::More';
test_requires 'Carp';
test_requires 'Catalyst::Authentication::Store::Minimal';
test_requires 'Catalyst::Test';
test_requires 'FindBin';
test_requires 'HTTP::Request::AsCGI';
test_requires 'HTTP::Server::Simple::CGI';
test_requires 'MIME::Base64';
test_requires 'Test::Pod';
test_requires 'Test::Pod::Coverage';

tests_recursive (qw|
    t
|);

resources 'license'     => 'http://dev.perl.org/licenses/';
resources 'repository'  => 'http://github.com/nigelm/Catalyst-Authentication-Credential-RemoteHTTP/';

auto_install;

WriteAll;
