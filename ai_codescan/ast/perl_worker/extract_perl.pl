#!/usr/bin/perl
# Perl AST worker. Speaks the same JSONL protocol as the Node worker in
# ``../node_worker/worker.mjs``: one JSON job per stdin line, JSONL records
# on stdout, one ``done`` record per job.
#
# Perl gets its own worker because no tree-sitter Perl grammar is ABI
# compatible with the pinned ``tree-sitter@0.22.4`` host binding (verified
# against tree-sitter-perl 1.0.3 / 1.1.4 / 1.2.1 — all fail inside
# ``getNodeTypeNamesById``). PPI is the canonical Perl static-analysis
# parser (it is what perlcritic builds on), so we shell out to it instead of
# regex-scanning the source.
#
# Emitted records match the Node worker exactly:
#   { "type":"file",   "file":..., "lang":"perl", "lineCount":N }
#   { "type":"symbol", "file":..., "kind":"function", "name":...,
#     "range":[startLine,endLine], "syntheticId":"synthetic:<sha1[0:12]>" }
#   { "type":"xref",   "kind":"call", "file":..., "line":N,
#     "callerSyntheticId":... , "calleeText":... }

use strict;
use warnings;
use PPI;
use JSON::PP;
use Digest::SHA qw(sha1_hex);

my $json = JSON::PP->new->canonical;

# Mirrors syntheticId() in the Node extractors so ids are stable across
# languages and reruns.
sub synthetic_id {
    my ( $file, $kind, $name, $line ) = @_;
    return 'synthetic:' . substr( sha1_hex("$file|$kind|$name|$line"), 0, 12 );
}

sub emit {
    my ($record) = @_;
    print $json->encode($record), "\n";
}

# Walk up the PPI tree to find the sub that lexically contains an element.
# Returns (name, start_line) or (undef, undef) for top-level code.
sub enclosing_sub {
    my ($elem) = @_;
    my $node = $elem->parent;
    while ($node) {
        if ( $node->isa('PPI::Statement::Sub') && $node->can('name') ) {
            my $name = $node->name;
            if ( defined $name && length $name ) {
                my $loc = $node->location;
                return ( $name, $loc ? $loc->[0] : 0 );
            }
        }
        $node = $node->parent;
    }
    return ( undef, undef );
}

# Build the call text for a word token. Perl calls come in several shapes and
# the entrypoint/sink regexes downstream match on this string, so we keep the
# receiver when there is one:
#   $cgi->param('x')   -> '$cgi->param'
#   DBI->connect(...)  -> 'DBI->connect'
#   system("...")      -> 'system'
sub callee_text {
    my ($word) = @_;
    my $prev = $word->sprevious_sibling;

    # Method call: <receiver> -> <word>
    if ( $prev && $prev->isa('PPI::Token::Operator') && $prev->content eq '->' ) {
        my $recv = $prev->sprevious_sibling;
        if ($recv) {
            my $recv_text = $recv->content;
            $recv_text =~ s/\s+//g;
            return $recv_text . '->' . $word->content;
        }
    }
    return $word->content;
}

# Words that are Perl syntax rather than calls. Emitting these as xrefs would
# bury the real call sites in noise.
my %NOT_A_CALL = map { $_ => 1 } qw(
    my our local state sub if elsif else unless while until for foreach
    do while return last next redo use no package require BEGIN END
    and or not xor eq ne lt gt le ge cmp qw q qq defined undef
);

sub process_file {
    my ($file) = @_;

    my $doc = eval { PPI::Document->new($file) };
    if ( !$doc ) {
        # A file PPI cannot parse must not kill the whole job — the rest of
        # the project still indexes. Skip it silently; prep reports coverage.
        return;
    }
    $doc->index_locations;

    my $src = '';
    if ( open my $fh, '<', $file ) {
        local $/;
        $src = <$fh> // '';
        close $fh;
    }
    my $line_count = ( $src =~ tr/\n// ) + 1;

    emit( { type => 'file', file => $file, lang => 'perl', lineCount => $line_count } );

    # --- subs -> symbol records ------------------------------------------
    my %sub_start_by_name;
    my $subs = $doc->find('PPI::Statement::Sub') || [];
    for my $sub (@$subs) {
        next if $sub->isa('PPI::Statement::Scheduled');    # BEGIN/END blocks
        my $name = $sub->name;
        next if !defined $name || !length $name;
        my $loc = $sub->location or next;
        my $start = $loc->[0];
        my $last = $sub->last_token;
        my $end = $last && $last->location ? $last->location->[0] : $start;
        $sub_start_by_name{$name} = $start;
        emit(
            {
                type        => 'symbol',
                file        => $file,
                kind        => 'function',
                name        => $name,
                range       => [ $start, $end ],
                syntheticId => synthetic_id( $file, 'function', $name, $start ),
            }
        );
    }

    # --- calls -> xref records -------------------------------------------
    my $words = $doc->find('PPI::Token::Word') || [];
    for my $word (@$words) {
        my $text = $word->content;
        next if $NOT_A_CALL{$text};

        my $prev = $word->sprevious_sibling;
        my $next = $word->snext_sibling;

        my $is_method = $prev
            && $prev->isa('PPI::Token::Operator')
            && $prev->content eq '->';

        # Parenthesised call: ``foo(...)``.
        my $has_args = $next && $next->isa('PPI::Structure::List');

        # Parenless call in command position: ``get '/user' => sub {...}``
        # (Mojolicious/Dancer routes), ``print $x``, ``system "cmd"``. Perl
        # lets any sub be called without parens, and the web-framework route
        # DSLs rely on it — these are exactly the entrypoints we must not
        # miss. Restricting to the first significant token of the statement
        # keeps ordinary barewords (hash keys, class names in the middle of
        # an expression) from being misread as calls.
        my $stmt         = $word->statement;
        my $first_in_stmt = $stmt && $stmt->schild(0) && $stmt->schild(0) == $word;
        my $bare_args =
            $next
            && ( $next->isa('PPI::Token::Quote')
            || $next->isa('PPI::Token::Number')
            || $next->isa('PPI::Token::Symbol')
            || $next->isa('PPI::Token::QuoteLike::Words')
            || $next->isa('PPI::Structure::Constructor') );
        my $is_parenless_call = $first_in_stmt && $bare_args;

        # Skip the sub's own declaration name.
        my $is_decl = $prev
            && $prev->isa('PPI::Token::Word')
            && $prev->content eq 'sub';

        next if $is_decl;
        next if !$is_method && !$has_args && !$is_parenless_call;

        my $loc = $word->location or next;
        my $line = $loc->[0];
        my ( $caller_name, $caller_line ) = enclosing_sub($word);
        my $caller_id =
            defined $caller_name
            ? synthetic_id( $file, 'function', $caller_name, $caller_line )
            : undef;

        emit(
            {
                type              => 'xref',
                kind              => 'call',
                file              => $file,
                line              => $line,
                callerSyntheticId => $caller_id,
                calleeText        => callee_text($word),
            }
        );
    }
}

# --- job loop ------------------------------------------------------------
$| = 1;
while ( my $line = <STDIN> ) {
    next if $line !~ /\S/;
    my $job = eval { $json->decode($line) };
    if ( !$job ) {
        emit( { type => 'error', message => 'perl worker: malformed job line' } );
        next;
    }
    my $ok = eval {
        for my $file ( @{ $job->{files} || [] } ) {
            process_file($file);
        }
        1;
    };
    if ( !$ok ) {
        my $err = $@ || 'unknown error';
        chomp $err;
        emit( { type => 'error', message => "perl worker: $err" } );
        next;
    }
    emit( { type => 'done', jobId => $job->{jobId} } );
}
