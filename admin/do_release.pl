#!/usr/bin/perl

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
  if 0;    # not running under some shell
use strict;
use warnings;

=head1 NAME

release - give your Perl distros to the world

=head1 SYNOPSIS

	release [OPTIONS] [ LOCAL_FILE [ REMOTE_FILE ] ]

	# try a dry run without uploading anything
	release -t

	# print a help message and exit
	release -h

	# skip kwalitee testing (e.g. a script distro)
	release -k

	# print debugging information
	release -d

	# print release number and exit
	release -v

	# set $ENV{AUTOMATED_TESTING} to a true value
	release -a
	

=head1 DESCRIPTION

This is the prototype program for using C<Module::Release>. You should
modify it to fit your needs. If it doesn't do what you want, you can
change it however you like. This is how I like to release my modules,
and I'm happy to add features that do not get in my way. Beyond that,
you should write your own script to match your process.

This program automates Perl module releases. It makes the
distribution, tests it, checks that source control is up to date, tags
source control, uploads it to the PAUSE anonymous FTP directory and
claims it on PAUSE.

By default this script assumes that you use CVS, but recognizes SVN
and git and switches when appropriate.

=head2 Process

The release script checks many things before it actually releases the
file.  Some of these are annoying, but they are also the last line of
defense against releasing bad distributions.

=over 4

=item Read the configuration data

Look in the current working directory for C<.releaserc>.  See the
Configuration section.  If release cannot find the configuration file,
it dies.

=item Test and make the distribution

Run make realclean, perl Makefile.PL, make test, make dist, make
disttest.  If testing fails, release dies.  make dist provides the
name of the distribution if LOCAL_FILE is not provided on the command
line. Too test the distribution against several perl binaries, see
the C<perls> configuration setting.

=item Check that source control is up-to-date

If there are modified files, added files, or extra files so that
source control complains, fail.

=item Upload to PAUSE

Simply drop the distribution in the incoming/ directory of PAUSE

=item Claim the file on PAUSE

Connect to the PAUSE web thingy and claim the uploaded file for your
CPAN account.

=item Tag the repository

Use the version number (in the distribution name) to tag the
repository.  You should be able to checkout the code from any release.

=back

=head2 Command-line switches

=over 4

=item -a

Set $ENV{AUTOMATED_TESTING} to true. You can also set automated_testing
in the configuration file.

=item -d

Show debugging information

=item -h

Print a help message then exit

=item -k

Skip the kwalitee checks. You can also set the skip_kwalitee directive
to a true value in the configuration file.

Have you considered just fixing the kwalitee though? :)

=item -p

Skip the prereq checks. You can also set the skip_prereqs directive
to a true value in the configuration file.

Have you considered just fixing the prereqs though? :)

=item -t

Run all checks then stop. Do not change any files or upload the distribution.

=item -v

Print the program name and version then exit

=back

=head2 Configuration

The release script uses a configuration file in the current working
directory.  The file name is F<.releaserc>.

release's own F<.releaserc> looks like this:

    cpan_user BDFOY

If you would like to test with multiple perl binaries (version 1.21
and later), list them as a colon-separated list in the C<perls>
setting:

	perls /usr/local/bin/perl5.6.2:/usr/local/bin/perl5.10.0

release does not test the perls in any particular order.

=over 4

=item cpan_user

The PAUSE user

=item passive_ftp

Set C<passive_ftp> to "y" or "yes" for passive FTP transfers.  Usually
this is to get around a firewall issue.

=item skip_kwalitee

Set to a false value to skip kwalitee checks (such as for a script
distribution with no modules in it).

=item skip_prereqs

Set C<skip_prereqs> to 1 if you don't want to run the Test::Prereq
checks. By default this is 0 and C<release> will try to check
prerequisites.

=item automated_testing

Set C<automated_testing> to the value you want for the 
$ENV{AUTOMATED_TESTING} setting. By default this is 0, so
testing is started in interactive mode.

=item release_subclass

DEPRECATED AND REMOVED. You should really just write your own
release script. Fork this one even!

=back

=head2 Environment

=over 4

=item * AUTOMATED_TESTING

Module::Release doesn't do anything with this other than set it for
Test::Harness.

=item * CPAN_PASS

release reads the C<CPAN_PASS> environment variable to set the
password for PAUSE.  Of course, you don't need to set the password for
a system you're not uploading to.

=item * RELEASE_DEBUG

The C<RELEASE_DEBUG> environment variable sets the debugging value,
which is 0 by default.  Set C<RELEASE_DEBUG> to a true value to get
debugging output.

=item * PERL

The C<PERL> environment variable sets the path to perl for use in the
make; otherwise, the perl used to run release will be used.

=back

=head1 TO DO

=over 4

=item * break out functional groups into modules.

=item * more plugins!

=back

=head1 SOURCE AVAILABILITY

This source is in Github as part of the Module::Release project:

        git://github.com/briandfoy/module-release.git

=head1 AUTHOR

brian d foy, C<< <bdfoy@cpan.org> >>

=head1 COPYRIGHT AND LICENSE

Copyright 2002-2008, brian d foy, All rights reserved.

You may use this software under the same terms as Perl itself.

=head1 CREDITS

Ken Williams turned the original release(1) script into a module.

Andy Lester contributed to the module and script.

H. Merijn Brand submitted patches to work with 5.005 and to create
the automated_testing feature.

=cut

use Getopt::Std;
use Pod::Readme;
use Module::Release;
use IO::File;
use POSIX qw(strftime);

my $class = "Module::Release";

sub make_vcs_tag {
    no warnings 'uninitialized';

    my ( $major, $minor ) =
      $_[0]->remote_file =~
      /(\d+) \. (\d+(?:_\d+)?) (?: \.tar\.gz | \.tgz | \.zip )? $/xg;

    $_[0]->_warn(
"Could not parse remote [$_[0]->{remote_file}] to get major and minor versions"
    ) unless defined $major;

    return "release/${major}.${minor}";
}

sub check_changes {
    my $release = shift;

    $release->_print("Checking Changes file\n");
    my $fh = IO::File->new( 'Changes', 'r' ) || die "Cannot find Changes file";
    my $version_line;
    while (<$fh>) {
        chomp;
        if (/^\d/) {

            # this must be a version tag
            $version_line = $_;
            last;
        }
    }
    my ( $version, $date ) = split( /\s+/, $version_line, 2 );

    # check version
    unless ( $version eq $release->dist_version ) {
        die "Version number in Changes file does not match release version";
    }

    # check date
    my $thisdate_re =
      strftime( '%a \s+ %e \s+ %b \s+ %Y', localtime( time() ) );
    unless ( $date =~ /$thisdate_re/x ) {
        die "Date for this version in Changes file is not today";
    }
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
my %opts;
getopts( 'ahdptvk', \%opts ) or $opts{h} = 1;

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
my ($script_version) = '2.00_04';

if ( $opts{v} ) {
    print "$0 version $script_version\n";
    exit;
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if ( $opts{h} ) {
    print <<"USE";

Use: release -hdktv [ LOCAL_FILE [ REMOTE_FILE ] ]

Will upload current release LOCAL_FILE, naming it REMOTE_FILE.  Will
get LOCAL_FILE and REMOTE_FILE automatically (using same name for
both) if not supplied.

	-h   This help
	-d   Print extra debugging information
	-k   Skip kwalitee check
	-t   Just make and test distribution, don't tag/upload
	-v   Print the script version number and exit

The program works in the current directory, and looks for a .releaserc
or releaserc file and the environment for its preferences.  See
`perldoc $0`, for more information.

USE

    exit;
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# get the release object
my %params;
$params{local} = shift @ARGV if @ARGV;

if (@ARGV) {
    $params{remote} = shift @ARGV;
}
elsif ( $params{local} ) {
    $params{remote} = $params{local};
}

$params{debug} = 1 if $opts{d};

my $release = $class->new(%params);

$release->_debug(
    "release $script_version, using $class " . $class->VERSION . "\n" );

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# load whatever will handle source control
{
    my @vcs = (
        [ '.git'       => "Module::Release::Git" ],
        [ '.gitignore' => "Module::Release::Git" ],
        [ '.svn'       => "Module::Release::SVN" ],
        [ 'CVS'        => "Module::Release::CVS" ],
    );

    foreach my $vcs (@vcs) {
        next unless -e $vcs->[0];

        my $module = $vcs->[1];

        $release->_debug(
            "I see an $vcs->[0] directory, so I'm loading $module\n");

        $release->load_mixin($module);

        die "Could not load $module: $@\n" if $@;

        last;
    }

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Will we upload to PAUSE?
if ( $release->config->cpan_user )    # not a dry run
{
    $release->load_mixin('Module::Release::PAUSE');
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Will we upload to PAUSE?
$release->load_mixin('Module::Release::Prereq');

my $skip_prereqs = $opts{p} || $release->config->skip_prereqs;

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set automated testing from command line, config, environment, or default
{
    no warnings 'uninitialized';

    $ENV{AUTOMATED_TESTING} = (
        grep { defined } (
            $opts{a},                $release->config->automated_testing,
            $ENV{AUTOMATED_TESTING}, 0
        )
    )[0];
    $release->_debug(
            "Automated testing is $ENV{AUTOMATED_TESTING}; -a was $opts{a};"
          . " automated_testing was "
          . $release->config->automated_testing
          . ";\n" );
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# test with a bunch of perls
{
    my $old_perl = $release->get_perl;

    foreach my $perl ( $release->perls ) {
        $release->_print("============Testing with $perl\n");
        $release->set_perl($perl) or next;

        $release->clean;
        $release->build_makefile;
        $release->make;
        $release->test;

        unless ($skip_prereqs) {
            $release->check_prereqs;
        }
        else {
            $release->_print("Skipping prereq checks. Shame on you!\n");
        }

        $release->dist;
        $release->disttest;
    }

    $release->set_perl($old_perl);
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# check kwalitee
unless ( $opts{k} || $release->config->skip_kwalitee ) {
    $release->load_mixin('Module::Release::Kwalitee');
    $release->_print("============Testing for kwalitee\n");
    $release->clean;
    $release->build_makefile;
    $release->make;
    $release->dist;
    $release->check_kwalitee;
}
else {
    $release->_print("Skipping kwalitee checks. Shame on you!\n");
}

# make sure README file is right
if ( -M 'lib/Catalyst/Authentication/Credential/RemoteHTTP.pm' < -M 'README' ) {
    $release->_print("Updating README file\n");
    my $parser = Pod::Readme->new();
    $parser->parse_from_file(
        'lib/Catalyst/Authentication/Credential/RemoteHTTP.pm', 'README' );
}
else {
    $release->_print("README file up to date\n");
}

# make sure MANIFEST is right
$release->check_manifest;
check_changes($release);

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# check source repository (but do not commit)
$release->_print("============Checking source repository\n");

$release->check_vcs;

my $Version = $release->dist_version;

$release->_debug("dist version is  $Version\n");

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# exit if this is a dry run. Everything following this changes
# things or uploads. Don't leave anything behind.

if ( $opts{t} ) {
    $release->distclean;
    unlink glob("*.tar*");
    exit;
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build the release in preparation for uploading
$release->clean;
$release->touch_all_in_manifest;
$release->build_makefile;
$release->make;
$release->dist;

$release->check_for_passwords;

$release->_debug("This is where I should release stuff\n");
while ( $release->should_upload_to_pause ) {
    $release->load_mixin('Module::Release::FTP');
    $release->_print("Now uploading to PAUSE\n");
    $release->_print("============Uploading to PAUSE\n");
    last if $release->debug;

    $release->ftp_upload( hostname => $release->pause_ftp_site );
    $release->pause_claim;
    last;
}

$release->vcs_tag unless $release->debug;

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
$release->clean;

$release->_print("Done.\n");

__END__
