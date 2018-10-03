use strict;
use warnings;
# use Digest::SHA1 qw/sha1_base64/;
use Data::Dumper;
use Digest::SHA qw/hmac_sha1 hmac_sha1_base64/;
use Digest::MD5 qw/md5_hex/;
use URI::Escape qw/uri_escape/;
use MIME::Base64;
use LWP::UserAgent;
use HTTP::Request;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my $ts = time();

my $base_url = 'http://nick:8080/';

sub request_token(){

    my HTTP::Request $req = HTTP::Request->new('POST', $base_url . '/plugins/servlet/oauth/request-token');

    my $ua = LWP::UserAgent->new();
}

sub authorize_token(){

}

sub make_authorized_request {
    my ($url) = @_;
}



# oauth_consumer_key=example
# oauth_signature_method=RSA-SHA1
# oauth_nonce=4149528333
# oauth_timestamp=1538391821
# oauth_token=Tct4nGSCCR5gk8juodNi3DeNabsK7dth
# oauth_signature=ThwYMOYoQb53woyVJFyaxeDit0uAyv6N5ejd3E9%2Bd%2FFwGJ09iZ8eWI2R6qOMjMTJkZaikDQSgyLgNPJeio0oiT7I8bg%2FUvwBhTIT5smnY%2FYX3CazB1qvCQ%2B%2F0RDN1lrvqSNfv5GQqXLwykjk%2B2n8If7QNXgJdpBK24EtgPHf0Gw%3D
# oauth_version=1.0

my $p = {
    oauth_consumer_key     => 'example',
    oauth_nonce            => $ts . $ts,
    oauth_timestamp        => $ts,
    oauth_signature_method => 'HMAC-SHA1',
    request_method         => "POST",
    oauth_version          => '1.0a',
    secret                 => join('', split("\n", 'MIICWwIBAAKBgQDOxQc+bK1Qpdq/C5TBLnKlviB5MuqmA82rvy5UKMEOq2Yu0jnQ
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
WdxK2YqN5hJNksVZefGiqXXgOrn3XHVZNKNRq3f6xw==')),
    base_url               => 'http://nick:8080/',
};


# print Dumper $p;

my $base_signature = sprintf('%s&%s&', $p->{request_method}, uri_escape($p->{base_url}));
print "Base: $base_signature\n";

my $new_url = $p->{base_url};
$new_url .= '?';

for my $k (qw/oauth_consumer_key oauth_nonce oauth_signature_method oauth_timestamp oauth_version/) {
    die "Missing $k" unless $p->{$k};
    # $base_signature .= sprintf('%s=%s&', $k, uri_escape($p->{$k}));
    my $ps = sprintf('%s=%s&', $k, $p->{$k});
    $base_signature .= uri_escape($ps);
    print "PS: $ps\n";
    $new_url .= sprintf('%s=%s&', $k, $p->{$k});
}

$base_signature =~ s/&$//gs;
# $new_url = $base_signature;
print "Got sign: $base_signature\n";

my $presign = uri_escape($p->{oauth_consumer_key}) . '&' . uri_escape($p->{secret});


print "Pre sign: $presign\n";
my $sign_key = $presign;
print "Secret sign: $sign_key\n";

# my $signature = encode_base64(hmac_sha1($base_signature, $sign_key)) . '=';
my $signature = hmac_sha1_base64($base_signature, $sign_key) . '=';
# my $signature = encode_base64(hmac_sha1($sign_key, $base_signature));
# my $signature = hmac_sha1($base_signature, $sign_key);

$new_url .= 'oauth_signature=' . uri_escape($signature);

 $signature =~ s/\s$//s;
print "Signature: $signature\n";
my $header_template = q|OAuth oauth_consumer_key="%s",oauth_timestamp="%s",oauth_signature_method="HMAC-SHA1",oauth_nonce="%s",oauth_version="1.0",oauth_signature="%s"|;

my $header = sprintf($header_template, uri_escape($p->{oauth_consumer_key}), uri_escape($p->{oauth_timestamp}), uri_escape($p->{oauth_nonce}), uri_escape($signature));

print "Header: $header \n";
print "New url:\n$new_url\n";

# Make authorized request
my $project = "TEST";
# my $req = HTTP::Request->new("GET" => $p->{base_url} . "rest/api/1.0/projects/" . $project);
my $req = HTTP::Request->new("GET" => $p->{base_url} . "/plugins/servlet/oauth/request-token"); #'/" . $project);
# my $req = HTTP::Request->new("GET" => $p->{base_url} . "rest/api/2/project"); #'/" . $project);
# my $req = HTTP::Request->new("GET" => $p->{base_url} . "rest/api/1.0/projects"); #'/" . $project);
$req->header('Authorization', $header);

my $ua = LWP::UserAgent->new();
my HTTP::Response $response = $ua->request($req);

print "\n";
print "Code: " . $response->code() . "\n";
print $response->decoded_content();

print "\n";
exit 0;





# print Dumper $response;
