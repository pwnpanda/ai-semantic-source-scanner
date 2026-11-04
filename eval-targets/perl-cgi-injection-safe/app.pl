#!/usr/bin/perl
# Negative eval target: same CGI entrypoints and the same user-controlled
# parameters as ../perl-cgi-injection/app.pl, written safely. The deterministic
# Perl layer must emit nothing here.
#
# Each sub below is the safe counterpart of the matching vulnerable one:
#   lookup_user     - bind values instead of interpolation
#   probe_host      - LIST-form system(), which bypasses the shell
#   read_report     - three-argument open with an explicit mode
#   apply_expression - no eval; arithmetic on a validated number
use strict;
use warnings;
use CGI;
use DBI;

my $q   = CGI->new;
my $dbh = DBI->connect( "dbi:SQLite:dbname=app.db", "", "" );

sub lookup_user {
    my ($id) = @_;
    return $dbh->selectrow_array( "SELECT name FROM users WHERE id = ?", undef, $id );
}

sub probe_host {
    my ($host) = @_;
    return if $host !~ /\A[A-Za-z0-9.-]+\z/;
    system( 'ping', '-c', '1', $host );
}

sub read_report {
    my ($name) = @_;
    return () if $name =~ m{[/\\]} || $name !~ /\A[\w.-]+\z/;
    open( my $fh, '<', "reports/$name" ) or die "open failed: $!";
    my @lines = <$fh>;
    close $fh;
    return @lines;
}

sub apply_expression {
    my ($expr) = @_;
    return 0 if $expr !~ /\A-?[0-9]+\z/;
    return 1 + $expr;
}

my $name   = lookup_user( $q->param('id') );
my @report = read_report( $q->param('report') );
probe_host( $q->param('host') );
my $total = apply_expression( $q->param('expr') );

print $q->header('text/plain');
print "user=$name total=$total lines=" . scalar(@report) . "\n";
