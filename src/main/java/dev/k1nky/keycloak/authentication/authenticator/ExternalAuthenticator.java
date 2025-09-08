package dev.k1nky.keycloak.authentication.authenticator;

import java.util.Map;

import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.broker.provider.util.SimpleHttp;

import java.io.IOException;
import java.util.stream.Collectors;

/**
 * @author Andrey Shalashov, https://github.com/k1nky, @k1nky
 */
public class ExternalAuthenticator implements Authenticator {

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		try {
			AuthenticatorConfigModel config = context.getAuthenticatorConfig();
			String timeout = config.getConfig().get(Constants.EXTERNAL_TIMEOUT_KEY);
			String url = config.getConfig().get(Constants.EXTERNAL_URL_KEY);

			SimpleHttp httpRequest = SimpleHttp.doPost(url, session);
			httpRequest.connectionRequestTimeoutMillis(Integer.parseInt(timeout));
			SimpleHttp.Response response = httpRequest.json(createPayload(user)).asResponse();
			int status = response.getStatus();
			if (status == HttpStatus.SC_OK) {
				context.success();
			} else if (status == HttpStatus.SC_FORBIDDEN) {
				context.failure(AuthenticationFlowError.ACCESS_DENIED,
					context.form().setError("access denied").createErrorPage(Response.Status.UNAUTHORIZED));
			} else {
				context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
					context.form().setError("unexpected response status code").createErrorPage(Response.Status.BAD_REQUEST));
			}
		} catch (IOException e) {
			context.failure(AuthenticationFlowError.INTERNAL_ERROR);
		}
	}

	private UserDto createPayload(UserModel user) {
		return new UserDto(
			user.getGroupsStream().map(GroupModel::getName).collect(Collectors.toList()),
			user.getRoleMappingsStream().map(RoleModel::getName).collect(Collectors.toList()),
			user.getAttributes().entrySet().stream().collect(
				Collectors.toMap(
					entry -> entry.getKey(),
					entry -> entry.getValue().isEmpty() ? null : entry.getValue().get(0)
				)
			)
		);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Nothing to do.
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}
}