# Net::OAuth::PP

Net::OAuth with contained Pure perl RSA libraries

## Dependencies
This module was made for situation when no non-core libraries could be used
You can omit using *Dependencies_RSA.pm* installing *Crypt::Perl* 

### Example application

  Using OAuth 1.0 for JIRA REST API
  
Use case from bin/app.pl
  
<pre>
my $token_to_use = $ARGV[0] || '';
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

print "Can make request with $Oauth->{oauth_token}\n";
print $Oauth->request('GET', $request_path, { param1 => 'value2' });

</pre>


### Missing features
  - OAuth 1.0a (not checked this, but verifier can be set)
  - OAuth 2.0
  - Link format (signature is sensitive to double slashes)
  
Feel free to send pull requests 