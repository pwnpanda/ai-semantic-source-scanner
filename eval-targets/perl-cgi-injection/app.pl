#!/usr/bin/perl
# Deliberately vulnerable CGI script - eval target for the Perl deterministic
# layer (Semgrep generic-mode rules in engines/semgrep_rules/perl-injection.yaml).
#
# Perl has no Joern frontend and no native Semgrep language support, so the
# generic-mode token rules plus the llm-heavy engine are the only passes that
# see this file. Every vulnerable line below is paired with a safe equivalent
# in ../perl-cgi-injection-safe/app.pl.
use strict;
use warnings;
use CGI;
use DBI;

my $q   = CGI->new;
my $dbh = DBI->connect( "dbi:SQLite:dbname=app.db", "", "" );

# CWE-89: the id parameter is interpolated into the statement text instead of
# being passed as a bind value.
sub lookup_user {
    my ($id) = @_;
    return $dbh->selectrow_array("SELECT name FROM users WHERE id = $id");
}

# CWE-78: single-argument system() is handed to the shell.
sub probe_host {
    my ($host) = @_;
    system("ping -c 1 $host");
}

# CWE-78: two-argument open honours mode characters inside the filename, so a
# value beginning with "|" is executed as a command.
sub read_report {
    my ($name) = @_;
    open( my $fh, "reports/$name" ) or die "open failed: $!";
    my @lines = <$fh>;
    close $fh;
    return @lines;
}

# CWE-95: string eval compiles its argument as Perl source.
sub apply_expression {
    my ($expr) = @_;
    return eval "1 + $expr";
}

my $name   = lookup_user( $q->param('id') );
my @report = read_report( $q->param('report') );
probe_host( $q->param('host') );
my $total = apply_expression( $q->param('expr') );

print $q->header('text/plain');
print "user=$name total=$total lines=" . scalar(@report) . "\n";
