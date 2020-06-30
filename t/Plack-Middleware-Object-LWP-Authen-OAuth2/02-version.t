use strict;
use warnings;

use Plack::Middleware::Object::LWP::Authen::OAuth2;
use Test::More 'tests' => 2;
use Test::NoWarnings;

# Test.
is($Plack::Middleware::Object::LWP::Authen::OAuth2::VERSION, 0.01, 'Version.');
