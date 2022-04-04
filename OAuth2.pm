package Plack::Middleware::Auth::OAuth2;

use base qw(Plack::Middleware);
use strict;
use warnings;

use English;
use Error::Pure qw(err);
use JSON::XS;
use LWP::Authen::OAuth2;
use Plack::App::Login;
use Plack::Response;
use Plack::Session;
use Plack::Util::Accessor qw(app_login app_login_url client_id client_secret
	logout_path lwp_user_agent redirect_path scope service_provider);

our $VERSION = 0.01;

sub call {
	my ($self, $env) = @_;

	my $session = Plack::Session->new($env);
	my $path_info = $env->{'PATH_INFO'};

	# Check.
	$self->_check_run($env);

	# Create OAuth2 object if doesn't exist.
	$self->_create_oauth2_object($env);

	# Auth page.
	if ($path_info eq '/'.$self->redirect_path) {
		return $self->_auth_code_app->($env);
	}

	# Logout page.
	if ($path_info eq '/'.$self->logout_path) {
		return $self->_app_logout->($env);
	}

	# Check authorized.
	my $authorized = $self->_authorized($env);

	# Application after authorization.
	if ($authorized) {
		return $self->app->($env);

	# Unauthorized page.
	} else {
		# TODO Nemel bych tady predat nejake dalsi veci?

		$self->app_login_url->($self->app_login,
			$session->get('oauth2')->authorization_url);
		return $self->app_login->to_app->($env);
	}
}

sub prepare_app {
	my $self = shift;

	if (! defined $self->client_id) {
		err "No OAuth2 'client_id' setting.";
	}

	if (! defined $self->client_secret) {
		err "No OAuth2 'client_secret' setting.";
	}

	if (! defined $self->app_login) {
		err 'No login application.';
		# TODO Default login app?
	}

	if (! defined $self->app_login_url) {
		err 'No login url call.';
		# TODO Check
	}

	if (! defined $self->redirect_path) {
		err 'No redirect path.';
	}

	if (! defined $self->service_provider) {
		err 'No service provider.';
	}

	if (! defined $self->logout_path) {
		$self->logout_path('logout');
	}

	return;
}

sub _app_logout {
	return sub {
		my $env = shift;

		my $session = Plack::Session->new($env);

		# Delete token string.
		if (defined $session->get('token_string')) {
			$session->remove('token_string');
		}

		# Redirect.
		my $res = Plack::Response->new;
		$res->redirect('/');

		return $res->finalize;
	};
}

sub _auth_code_app {
	return sub {
		my $env = shift;

		my $req = Plack::Request->new($env);

		my $session = Plack::Session->new($env);

		# Process token string.
		my $oauth2_code = $req->parameters->{'code'};
		if (! defined $oauth2_code) {
			return [
				400,
				['Content-Type' => 'text/plain'],
				['No OAuth2 code.'],
			];
		}
		$session->get('oauth2')->request_tokens('code' => $oauth2_code);

		my $token_string_json = $session->get('oauth2')->token_string;
		my $token_string_hr = JSON::XS->new->decode($token_string_json);
		$session->set('token_string', $token_string_hr);

		# Redirect.
		my $res = Plack::Response->new;
		$res->redirect('/');

		return $res->finalize;
	};
}

sub _authorized {
	my ($self, $env) = @_;

	my $session = Plack::Session->new($env);

	# No token string.
	if (! defined $session->get('token_string')) {
		return 0;
	}

	# No OAuth2 object.
	if (! defined $session->get('oauth2')) {
		return 0;
	}

	return 1;
}

sub _check_run {
	my ($self, $env) = @_;

	if (! defined $env->{'psgix.session'}) {
		err "No Plack::Middleware::Session present.";
	}

	return;
}

# Create OAuth2 object in session.
sub _create_oauth2_object {
	my ($self, $env) = @_;

	my $session = Plack::Session->new($env);

	# Object is created in session.
	if (defined $session->get('oauth2')) {
		return;
	}

	# XXX Automatically https?
	my $redirect_uri = 'https://'.$env->{'HTTP_HOST'};
	if (! defined $redirect_uri) {
		err 'Missing host.'
	}
	my $redirect_path = $self->redirect_path;
	$redirect_uri .= '/'.$redirect_path;

	# Create object.
	my $oauth2 = eval {
		LWP::Authen::OAuth2->new(
			'client_id' => $self->client_id,
			'client_secret' => $self->client_secret,
			'redirect_uri' => $redirect_uri,
			$self->scope ? ('scope' => $self->scope) : (),
			'service_provider' => $self->service_provider,
		);
	};
	if ($EVAL_ERROR) {
		err "Cannot create OAuth2 object.",
			'Error', $EVAL_ERROR,
		;
	}
	if ($self->lwp_user_agent) {
		$oauth2->set_user_agent($self->lwp_user_agent);
	}
	$session->set('oauth2', $oauth2);

	# Save service provider to session.
	$session->set('oauth2.service_provider', $self->service_provider);

	return;
}

1;

__END__

