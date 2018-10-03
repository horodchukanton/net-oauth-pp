# Atlassian Perl OAuth Example (including a simple re-usable OAuth package)

This is an example of connecting with an Atlassian product's OAuth service in Perl, thus allowing secure access to the REST API.  This example was written for and tested with Stash but should work for any OAuth provider.

## Requirements

The following Perl packages are required and may not be part of your standard Perl distribution:

* LWP
* Crypt::OpenSSL::RSA
* URI
* HTTP::Request::Common
* Digest::SHA1
* Net::OAuth
* File::Which
* File::HomeDir
* JSON (recomended)

Your package manager may have versions of these available, if not all can be found on CPAN.

## OAuth.pm

The bulk of the code is in this example is the OAuth.pm package.  This package has a number of features for dealing with OAuth:

1. Basic OAuth authentication for protocol versions 1.0 (no callbacks or verifier code) and 1.0a (callbacks and verifier code).
2. A simple method to send a request to the connected server using the OAuth credentials.
3. The ability to save/load access tokens to flat file in a non human readable format (default file name can be generated based on sha1 hex digest of url).

This package contains default values for all configuration options suitable for the example set-up listed in this repository, all options can be over-ridden via the new(...) constructor.  If using this package in production the suggested route is to update the _initialise() method to contain default values suitable for your set-up.

It is worth noting that this package is not specific to Atlassian products and should be able to negotiate an OAuth connection to any simple 1.0/1.0a provider.

The package is fully documented using POD format.  Simply look at the file or run:

    pod2text OAuth.pm 
    
to get human readable documentation for the class and all public methods.

### A note on protocol versions

Atlassian documents their products as supporting protocol version 1.0a, this implicitly gives support for 1.0 as well.

The main difference is the use of the callback URL and verifier string in 1.0a.  This is sensible for web service to web service linking where the callback allows the client service to known when the request has been accepted and the verifier prevents certain classes of "man in the middle" attack.

For command line tools however the callback and verifier can be problematic without setting up a dedicated page to display the verifier to the user and asking them to copy/paste it in to the terminal.  As such the 1.0 version of the protocol is probably more suitable as it does not use the callback URL or verifier string.

### A note on Net::OAuth::Client and Net::OAuth::Simple

There are two Perl modules on CPAN that do the same things as this module (and a lot more besides): Net::OAuth::Client and Net::OAuth::Simple.

Both of these have one major notable flaw.  They are hard coded to use HTTP GET requests during the authentication process.  Atlassian products expect (and only work when) those requests are sent as POST requests.

You could simply acquire one of those packages and hack the source to work around this issue but the included OAuth.pm provides a simpler more minimalistic interface with a few extra nice features.

## Example OAuth.pl

This simple example application should be run twice.

The first time you run it it will attempt to acquire a OAuth token from the configured server, it will then save this token to:

    <user home>/.stash/oauth/<some file>

The second time (and all subsequent times) you run it it will detect the presence of this key file, load it and attempt to use the credentials to make a request to the server.

The request in this example assumes a Stash server and asks for all repositories from the project with the slug "CST".  You should change this to a query suitable for your server.

Some notes:

* The params for the query (limit, starting page etc.) are not passed in in the url but as a hash, this saves the caller having to do the URL encoding.
* Extra headers such as restricting output to JSON can also be passed in as a hash.
* The JSON::from_json(...) method is especially useful here to convert the return result in to raw Perl data structures.
* To re-issue the initial OAuth request simply delete the saved token file from the .stash directory.
