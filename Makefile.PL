use inc::Module::Install;

if ( $Module::Install::AUTHOR ) {
    system( 'pod2text lib/Catalyst/Authentication/Credential/RemoteHTTP.pm > README' )
        and die;
}

name     'Catalyst-Authentication-Credential-RemoteHTTP';
all_from 'lib/Catalyst/Authentication/Credential/RemoteHTTP.pm';
author   q{Nigel Metheringham <nigelm@cpan.org>};
license  'perl';

requires 'Catalyst::Runtime';
requires 'Class::Accessor::Fast';
requires 'Class::Inspector';
requires 'MRO::Compat';

build_requires 'Test::More';
build_requires 'Catalyst::Authentication::Store::Minimal';
build_requires 'FindBin';
build_requires 'HTTP::Server::Simple';

tests_recursive (qw|
    t
|);

resources 'license'     => 'http://dev.perl.org/licenses/';
resources 'repository'  => 'http://github.com/nigelm/Catalyst-Authentication-Credential-RemoteHTTP/';

auto_install;

WriteAll;
