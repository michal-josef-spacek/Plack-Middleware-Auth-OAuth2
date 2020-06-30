use strict;
use warnings;

use Test::NoWarnings;
use Test::Pod::Coverage 'tests' => 2;

# Test.
pod_coverage_ok('Plack::Middleware::Object::LWP::Authen::OAuth2', 'Plack::Middleware::Object::LWP::Authen::OAuth2 is covered.');
