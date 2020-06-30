package Plack::Middleware::Object::LWP::Authen::OAuth2;

use base qw(Plack::Middleware);
use strict;
use warnings;

use Error::Pure qw(err);
use LWP::Authen::OAuth2;
use Plack::Session;

our $VERSION = 0.01;

sub call {
	my ($self, $env) = @_;

	# Session.
	my $session = Plack::Session->new($env);

	if (! defined $env->{'psgix.session'}) {
		err "No Plack::Middleware::Session present.";
	}

	# Create OAuth2 object if doesn't exist.
	my $oauth2 = $session->get('oauth2');
	if (! defined $oauth2) {

		# Checks.
		if (! defined $self->{'client_id'}) {
			err 'Missing client ID.';
		}
		if (! defined $self->{'client_secret'}) {
			err 'Missing client secret.';
		}

		my $redirect_uri = $env->{'HTTP_HOST'};
		if (! defined $redirect_uri) {
			err 'Missing host.'
		}
		my $redirect_path = $self->{'redirect_path'} || 'oauth2_redirect';
		$redirect_uri .= '/'.$redirect_path;

		# Create object.
		$oauth2 = LWP::Authen::OAuth2->new(
			'client_id' => $self->{'client_id'},
			'client_secret' => $self->{'client_secret'},
			'redirect_uri' => $redirect_uri,
			'scope' => $self->{'scope'} || 'profile email',
			'service_provider' => $self->{'service_provider'} || 'Google',
		);
		$session->set('oauth2', $oauth2);
	}

	return $self->app->($env);
}

1;

__END__

