package Crypt::LE::ChallengeWithFallback;

use strict;
use warnings;

use parent 'Crypt::LE';

use Crypt::LE qw( OK );

sub accept_challenge {
    my ( $self, $cb, $params, $type ) = @_;

    # For non-dns challenges, use parent behavior
    return $self->SUPER::accept_challenge( $cb, $params, $type )
        unless $type eq 'dns';

    # Store original state
    my $full_challenges        = $self->{challenges};
    my $full_domains           = $self->{loaded_domains};
    my $full_active_challenges = $self->{active_challenges};

    # Filter to only keep wildcard domains
    my $wildcard_challenges = {};
    my @wildcard_domains;
    foreach my $domain (@$full_domains) {
        next unless $domain =~ /^\*\./;    # only wildcards
        if ( exists $full_challenges->{$domain} ) {
            $wildcard_challenges->{$domain} = $full_challenges->{$domain};
            push @wildcard_domains, $domain;
        }
    }

    # Temporarily replace with filtered set
    $self->{challenges}        = $wildcard_challenges;
    $self->{loaded_domains}    = \@wildcard_domains;
    $self->{active_challenges} = {};    # Start fresh for DNS challenges

    # Let parent handle the actual validation with filtered domains
    my $status = $self->SUPER::accept_challenge( $cb, $params, $type );

    if ( $status == OK ) {

        # Merge the active challenges back
        $self->{active_challenges} = {
            %{ $full_active_challenges || {} },
            %{ $self->{active_challenges} || {} }
        };
    }

    # Restore remaining original state
    $self->{challenges}     = $full_challenges;
    $self->{loaded_domains} = $full_domains;

    return $status;
}

# Override verify_challenge to only verify wildcards for DNS
sub verify_challenge {
    my ( $self, $cb, $params, $type ) = @_;

    return $self->SUPER::verify_challenge( $cb, $params, $type )
        unless $type && $type eq 'dns';

    # Store original state
    my $full_domains = $self->{loaded_domains};

    # Filter to only verify wildcard domains
    my @wildcard_domains = grep { /^\*\./ } @$full_domains;
    $self->{loaded_domains} = \@wildcard_domains;

    # Let parent handle verification
    my $status = $self->SUPER::verify_challenge( $cb, $params, $type );

    # Restore original state
    $self->{loaded_domains} = $full_domains;

    return $status;
}

1;

=head1 NAME

Crypt::LE::ChallengeWithFallback - Handle DNS challenges with fallback for wildcard domains

=head1 SYNOPSIS

  use Crypt::LE::ChallengeWithFallback;

  my $challenge = Crypt::LE::ChallengeWithFallback->new();
  my $status = $challenge->accept_challenge($callback, $params, 'dns');
  my $verify_status = $challenge->verify_challenge($callback, $params, 'dns');

=head1 DESCRIPTION

Crypt::LE::ChallengeWithFallback is a subclass of Crypt::LE that provides specialized handling for DNS challenges, particularly focusing on wildcard domains. This module exists to allow for a mixture of wildcard and non-wildcard domains to be validated at the same time. First, we try HTTP validation. Since this does not work for wildcard domains, those are attempted when HTTP fails. We do this to avoid DNS challenges when possible.

=head1 METHODS

=head2 accept_challenge

  $status = $challenge->accept_challenge($callback, $params, $type);

Overrides the parent method to handle DNS challenges specifically for wildcard domains. It temporarily filters the challenges to only include wildcard domains, processes them, and then restores the original state.

=head2 verify_challenge

  $status = $challenge->verify_challenge($callback, $params, $type);

Overrides the parent method to verify DNS challenges specifically for wildcard domains. It temporarily filters the loaded domains to only include wildcard domains, verifies them, and then restores the original state.

=head1 AUTHOR

Olaf Alders <olaf@wundersolutions.com>

=cut
