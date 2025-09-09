package dev.k1nky.keycloak.authentication.authenticator;

import jakarta.ws.rs.core.Response;

import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.broker.provider.util.SimpleHttp;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Andrey Shalashov, https://github.com/k1nky, @k1nky
 */
public class ExternalAuthenticator implements Authenticator {
	public static final Logger log = Logger.getLogger(ExternalAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		
		try {
			Map<String, String> config = context.getAuthenticatorConfig().getConfig();
			String url = config.get(Constants.EXTERNAL_URL_KEY);
			int timeout = getIntConfigProperty(config, Constants.EXTERNAL_TIMEOUT_KEY);

			if (StringUtil.isBlank(url)) {
				context.attempted();
				log.warn("URL is empty, skipping");
				return;
			}

			SimpleHttp httpRequest = SimpleHttp.doPost(url, session);
			httpRequest.connectionRequestTimeoutMillis(timeout);
			UserDto payload = createPayload(user);
			SimpleHttp.Response response = httpRequest.json(payload).asResponse();
			int status = response.getStatus();
			if (status == HttpStatus.SC_OK) {
				context.success();
			} else if (status == HttpStatus.SC_FORBIDDEN || status == HttpStatus.SC_UNAUTHORIZED) {
				context.failure(
					AuthenticationFlowError.ACCESS_DENIED,
					context.form().setError("access denied").createErrorPage(Response.Status.UNAUTHORIZED)
				);
			} else {
				log.errorf("unexpected response status code: %d from %s", status, url);
				context.failure(
					AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
					context.form().setError("unexpected response status code").createErrorPage(Response.Status.BAD_REQUEST)
				);
			}
		} catch (IOException e) {
			log.errorf("Unexpected error: %s", e.getMessage());
			context.failure(AuthenticationFlowError.INTERNAL_ERROR);
		}
	}

	private int getIntConfigProperty(Map<String, String> config, String key) {
		String value = config.get(key);
		if (StringUtil.isBlank(value)) {
			return -1;
		}
		return Integer.parseInt(value);
	}

	private UserDto createPayload(UserModel user) {
		Map<String, String> attributes = new HashMap<>();
		for (Map.Entry<String, List<String>> entry : user.getAttributes().entrySet()) {
			attributes.put(entry.getKey(), entry.getValue().isEmpty() ? "" : entry.getValue().get(0));
		}
		return new UserDto(
			user.getGroupsStream().map(GroupModel::getName).collect(Collectors.toList()),
			user.getRoleMappingsStream().map(RoleModel::getName).collect(Collectors.toList()),
			attributes
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