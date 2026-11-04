#!/usr/bin/perl
# Deliberately vulnerable Mojolicious::Lite fixture for scanner tests.
#
# Ground truth:
#   - CWE-89 SQL injection: the ``id`` query parameter is interpolated into
#     the SELECT handed to DBI instead of being passed as a bind value.
#   - CWE-78 command injection: the ``host`` parameter is interpolated into a
#     one-argument ``system`` call, which goes through the shell.
use strict;
use warnings;
use Mojolicious::Lite;
use DBI;

my $dbh = DBI->connect( "dbi:SQLite:dbname=app.db", "", "" );

sub lookup_user {
    my ($id) = @_;
    # VULNERABLE: $id is interpolated straight into the statement.
    return $dbh->selectrow_array("SELECT name FROM users WHERE id = $id");
}

get '/user' => sub {
    my $c    = shift;
    my $id   = $c->param('id');
    my $name = lookup_user($id);
    $c->render( text => "Hello $name" );
};

get '/ping' => sub {
    my $c    = shift;
    my $host = $c->param('host');
    # VULNERABLE: one-arg system() runs through the shell.
    system("ping -c 1 $host");
    $c->render( text => 'pong' );
};

app->start;
