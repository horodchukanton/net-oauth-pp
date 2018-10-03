#!/usr/bin/perl

use strict vars;
use Data::Dumper;
use JSON;
use OAuth;

# Create new OAuth object
my $oauth = OAuth->new(prot_version => "1.0",
    url                             => "http://nick:8080/",
    auth_callback                   => "http://nick/commander/link/projectDetails/plugins/EC-JIRA-1.1.4.146/project?objectId=plugin-7e0c626b-8906-11e8-92b3-0242ac110002&tabGroup=properties&s=Administration&ss=Plugins", # Callback ignored if prot_version isn't "1.0a"
    consumer_key                    => 'example',
    rsa_public_key_str              => '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOxQc+bK1Qpdq/C5TBLnKlviB5
MuqmA82rvy5UKMEOq2Yu0jnQizxmi1f7TISofBgQFNmlymhl4q/SUqYnGf601fCF
1rWcWaS2GQFsPEjilL0y0vzGE1sG02I4i3sbpS79Y5btgxhobD8drgWuL/IitczA
ZlVII5pweNdncB+uQwIDAQAB
-----END PUBLIC KEY-----
',
    rsa_private_key_str             => '-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'

);

# Atempt to load access tokens from default file store
# don't treat failure as a critical error and instead continue
$oauth->load_access_token_crypt_from_file("", nocroak => 1);

# Check to see if we got a valid access token from file
if (!$oauth->has_access_token())
{
  print "No saved access token\n";
  
  # Send initial request
  $oauth->request_request_token();

  # Get the authorization url and display it
  my $authUrl = $oauth->generate_auth_request_url();
  print "Auth request URL: $authUrl\n";

  # For 1.0a we need to ask for the verifier, for 1.0 just waiting until they verify is enough
  if ($oauth->prot_version() eq "1.0a")
  {
    print "Enter verifier: ";
    my $verifier = <STDIN>;
    chomp($verifier);

    $oauth->request_access_token($verifier);  
  }
  else
  {
    print "<Press return once you have accepted request>";
    <STDIN>;

    $oauth->request_access_token();  
  }
  
  # Store out the access token to file in an non-human readable form
  $oauth->save_access_token_crypt_to_file();
  
  print "Access token saved: " . join(" - ", $oauth->get_access_token()) . "\n";
}
else
{
  print "Access token restored: " . join(" - ", $oauth->get_access_token()) . "\n";
  
  # Try out a simple request to get all repositories for a named project
  my $project = "TEST";
  my $response = $oauth->make_request("GET",
                                      '/rest/auth/latest/session',
                                       # params  => {limit => 500, start => 0},
                                       headers => {Accepts => "application/json"});
                               
  # If a success convert the results from JSON and dump them, otherwise show an error        
  if ($response->is_success)
  {
    my $result = from_json($response->content);
    print Dumper($result);
  }
  else
  {
    print "Request failed: " . $response->status_line . "\n";
    unlink $oauth->get_crypt_file_path();
  }
}
