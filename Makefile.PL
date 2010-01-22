use inc::Module::Install;

name     'Catalyst-Authentication-Credential-RemoteHTTP';
all_from 'lib/Catalyst/Authentication/Credential/RemoteHTTP.pm';
author   q{Nigel Metheringham <nigelm@cpan.org>};
license  'perl';

requires 'Catalyst::Runtime';
requires 'Catalyst::Authentication::Credential::Password';
requires 'Class::Inspector';
requires 'MRO::Compat';

build_requires 'Test::More';

auto_install;

WriteAll;
