use strict;
use warnings;

our $Bin;
BEGIN {
    use FindBin '$Bin';
    unshift @INC, "$Bin/../lib";
}

use EC::Plugin::OAuth;


my $PRIVATE_KEY = ( '-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDOxQc+bK1Qpdq/C5TBLnKlviB5MuqmA82rvy5UKMEOq2Yu0jnQ
izxmi1f7TISofBgQFNmlymhl4q/SUqYnGf601fCF1rWcWaS2GQFsPEjilL0y0vzG
E1sG02I4i3sbpS79Y5btgxhobD8drgWuL/IitczAZlVII5pweNdncB+uQwIDAQAB
AoGAdvjdcyi7DLVxyQ1T2VftdbqRGsuWQlHb7J+De787XkJ2+CfURk9nQKWaySi9
B+jnO5GTrhZpvX4SppURr1wAtmmxdFlezfmeMA1ox7lN7F20myyVcQ61OZG2VPfu
dGvuIOLWeQDP63SSSE0Vbzv8KVi0hQ/NR/IXNJA4wUMAUakCQQDrcs35Xnh6Ah0i
87qhemm2D11Xk/v5Op5/mHANrKSiiujL+qns//KBM2hVlu7xCc1HBMXzwsPGENfF
tHCexKnfAkEA4NFiK58QwNw66VNYpK/J84xPvaaLCGYncmZUN6QdH6ObQXUszRJv
5mB2BElu+MT7ZnIFDK0r9W4EDHLBuxWQHQJAQ8GqHNVe/l2VXPWfA9Fiko4hYo6n
uLVx325S8Nx6FHy9OdZNCHMvqpbMs7TX1m3nsURiYx/tjxZRwgeHUWlvKQJAVkLA
wjAEQ5u81u3t4zK38ET0C7atPgnENPbidX741bz2w0TsbbsXSHPWlIqAk98w/vvc
yCJh7YfK8ePORbReWQJAbTwLkwxQlZ4VV2D7G6aZPcoByxkrM1iXaqTmw67EHqqB
WdxK2YqN5hJNksVZefGiqXXgOrn3XHVZNKNRq3f6xw==
-----END RSA PRIVATE KEY-----' );

# OAuth 1.0 is secure over insecure channels as long as you are using unique nonce each time
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my $base_url = 'http://nick:8080/';

my $token_to_use = $ARGV[0];
my $request_path = $ARGV[1] || 'rest/auth/latest/session';

my %PARAMS = (
    base_url               => $base_url,
    request_method         => 'POST',

    # HMAC-SHA1 is rejected by JIRA, using RSA-SHA1
    oauth_signature_method => 'RSA-SHA1',
    oauth_version          => '1.0',
    oauth_consumer_key     => 'example',

    request_token_path     => 'plugins/servlet/oauth/request-token',
    authorize_token_path   => 'plugins/servlet/oauth/authorize',
    access_token_path      => 'plugins/servlet/oauth/access-token',

    private_key            => $PRIVATE_KEY,
    # Will be set by a call to _renew_nonce()
    # oauth_nonce            => $ts . $ts,
    # oauth_timestamp        => $ts,

    # secret                 => 'example'
);

my $Oauth = EC::Plugin::OAuth->new(%PARAMS);
$Oauth->{oauth_token} = $token_to_use;

if (! $Oauth->{oauth_token}) {

    $Oauth->request_token();

    print "Auth request URL: " . ( $Oauth->generate_auth_url() ) . "\n";
    print "<Press return once you have accepted request>";
    <STDIN>;

    if ($Oauth->authorize_token()) {
        print "Authorized token: $Oauth->{oauth_token}\n";
    }
    else {
        die "No REST for the wicked \n";
    }
}

print "Will make request with $Oauth->{oauth_token}\n";

my $path = $request_path || 'rest/auth/latest/session';
print $Oauth->request('GET', $path, { param1 => 'value2' });

exit 0;

1;