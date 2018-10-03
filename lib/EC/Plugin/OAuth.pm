package EC::Plugin::OAuth;

use strict;
use warnings;

use Data::Dumper;
use Carp;

use URI;
use URI::Escape qw/uri_escape/;
use MIME::Base64 qw/encode_base64/;

use LWP::UserAgent;
use HTTP::Request;

sub new {
    my ( $class, %p ) = @_;

    my $self = { %p };

    return bless($self, $class);
}

sub request {
    my ( $self, $method, $path, $request_params ) = @_;

    my %params = ( %{ $request_params ? $request_params : {} } );

    $self->renew_nonce();

    # OAuth params are stored in self
    my @oauth_keys = qw/oauth_consumer_key oauth_nonce oauth_signature_method oauth_timestamp oauth_version/;
    push(@oauth_keys, 'oauth_token') if ($self->{oauth_token});

    foreach my $oauth_k (@oauth_keys) {
        croak "Missing OAuth parameter $oauth_k" unless $self->{$oauth_k};
        $params{$oauth_k} = $self->{$oauth_k};
    }

    # Calculate signature
    my $sign = $self->calculate_the_signature($path, $method, %params);

    # Prepare your content
    my %request_params = (
        %params,
        oauth_signature => MIME::Base64::encode_base64($sign, ''),
    );

    for my $k (keys %params) {
        croak "Missing value for $k" unless $params{$k};
        $request_params{$k} = uri_escape($params{$k});
    }

    my URI $url_with_oauth = URI->new($self->{base_url} . $path);
    $url_with_oauth->query_form(\%request_params);

    my HTTP::Request $req = HTTP::Request->new($method, $url_with_oauth);

    my $ua = LWP::UserAgent->new();
    my HTTP::Response $res = $ua->request($req);

    if (my @auth_headers = $res->header('www-authenticate')) {
        my $auth_response = $auth_headers[1] || $auth_headers[0];
        $auth_response =~ /oauth_problem="([a-z_]+)",?/ if $auth_response;
        die "OAUTH PROBLEM: " . $1 . "\n" if $1;
    }

    my $content = $res->decoded_content();
    die 'No content in response' if ! $content;

    return $content;
}

sub parse_token_response {
    my ( $self, $content ) = @_;

    my $resp = _parse_url_encoded($content);

    if ($resp->{oauth_problem}) {
        print "OAuth problem: $resp->{oauth_problem}";
        return undef;
    }

    if ($self->{oauth_token_secret} && $self->{oauth_token_secret} ne $resp->{oauth_token_secret}) {
        croak "Someone has tampered request. OAuth token secrets not are equal"
    }

    $self->{oauth_token} = $resp->{oauth_token};
    $self->{oauth_token_secret} = $resp->{oauth_token_secret};

    return( $resp->{oauth_token}, $resp->{oauth_token_secret} );
}


sub request_token {
    my ( $self ) = @_;
    my $response = $self->request($self->{request_method}, $self->{request_token_path});
    $self->parse_token_response($response);
}

sub authorize_token {
    my ( $self ) = @_;
    my $response = $self->request($self->{request_method}, $self->{access_token_path});
    $self->parse_token_response($response);
}


sub generate_auth_url {
    my ( $self, $token, %extra_params ) = @_;

    $token ||= $self->{oauth_token};

    die 'No request token' unless $token;

    my $oauth_url = URI->new($self->{base_url} . $self->{authorize_token_path});
    $oauth_url->query_form({
        oauth_token => $token,
        %{( %extra_params ) ? \%extra_params : {}}
    });

    return $oauth_url;
}


sub calculate_the_signature {
    my ( $self, $path, $method, %request_params ) = @_;

    my @oauth_params = ();
    for my $k (sort keys %request_params) {
        croak "Missing $k \n" unless $request_params{$k};
        push(@oauth_params, "$k=$request_params{$k}");
    }

    my @sign_parameters = ();
    push(@sign_parameters, $method);
    push(@sign_parameters, _encode($self->{base_url} . $path));
    push(@sign_parameters, _encode(join('&', @oauth_params)));

    my $sign_base_string = join('&', @sign_parameters);

    if ('RSA-SHA1' eq $self->{oauth_signature_method}) {

        #TODO: REMOVE ME IN PROD
        require "Dependencies_RSA.pm";

        croak("Private key is missing") unless $self->{private_key};

        Crypt::Perl::RSA::Parse->import();
        Crypt::Perl::RSA::PrivateKey->import();

        my $prv_key = Crypt::Perl::RSA::Parse::private($self->{private_key});
        my $sign = $prv_key->sign_RS1($sign_base_string);

        die "Signature length incorrect \n" unless (length $sign == 128);

        return $sign;
    }
    if ('HMAC-SHA1' eq $self->{oauth_signature_method}) {
        my $secret = $self->{oauth_secret};
        require Digest::SHA;
        Digest::SHA->import(qw/hmac_sha1/);

        croak 'Not sure about params for hmac_sha1';
        return Digest::SHA::hmac_sha1($secret . '&' . $sign_base_string);
    }

    die "Unknown signature method: $self->{oauth_signature_method}\n";
}

sub renew_nonce {
    my ( $self ) = @_;

    my $ts = time();

    $self->{oauth_timestamp} = $ts;
    $self->{oauth_nonce} = $ts . int(rand(2 ** 32));
}


sub _encode {
    my ( $str ) = @_;
    return URI::Escape::uri_escape_utf8($str, '^\w.~-')
}

sub _parse_url_encoded {
    my ( $query ) = @_;
    return unless $query;

    # Parse query
    my %query_params = ();
    my @pairs = split('&', $query);

    foreach my $pair (@pairs) {
        next unless $pair;
        my ( $k, $v ) = split('=', $pair);
        next unless $k;
        $query_params{$k} = $v || '';
    }

    return \%query_params;
}

1;
