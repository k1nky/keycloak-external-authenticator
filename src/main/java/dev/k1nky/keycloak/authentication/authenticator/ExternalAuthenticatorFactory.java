package dev.k1nky.keycloak.authentication.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author Andrey Shalashov, https://github.com/k1nky, @k1nky
 */
public class ExternalAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "external-authenticator";

	private static final Authenticator SINGLETON = new ExternalAuthenticator();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "External HTTP Authentication";
	}

	@Override
	public String getHelpText() {
		return "Call an external HTTP service for authentication.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {		
		ProviderConfigProperty externalUrl = new ProviderConfigProperty();
		externalUrl.setName(Constants.EXTERNAL_URL_KEY);
		externalUrl.setLabel("External HTTP service URL");
		externalUrl.setHelpText("");
		externalUrl.setType(ProviderConfigProperty.STRING_TYPE);

		ProviderConfigProperty externalTimeout = new ProviderConfigProperty();
		externalTimeout.setName(Constants.EXTERNAL_TIMEOUT_KEY);
		externalTimeout.setLabel("External HTTP service call timeout (in ms)");
		externalTimeout.setHelpText("");
		externalTimeout.setType(ProviderConfigProperty.STRING_TYPE);
		externalTimeout.setDefaultValue(Constants.DEFAULT_EXTERNAL_TIMEOUT_MS);

		return List.of(externalUrl, externalTimeout);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}