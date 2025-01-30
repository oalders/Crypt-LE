#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 2;

BEGIN {
    use_ok( 'Crypt::LE' ) || print "Bail out!\n";
    use_ok( 'Crypt::LE::ChallengeWithFallback' ) || print "Bail out!\n";
}

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Perl $], $^X" );
