# keycloak-external-authenticator

## Overview

The extension can be used in Keycloak authentication flows and allows calling an external service via HTTP. A typical use case is when user authentication requires not only login and passwords, but also confirmation from an external service. For example, an external service sends a push notification and checks the response to it.

### Example

You have an authentication flow consisting of the following steps:
1. User validation
2. Password
3. External HTTP Authentication (this extension) where "External HTTP service URL" set to "https://my-service/auth"

In step 3, the extension send structured JSON payload about the user to https://my-service/auth and waits for the service to respond with a decision (allow or deny).

## Requirements

* Java 17 or higher
* Keycloak 26.1.5 or a compatible version
* Maven for building the project

## Installation

1. Build the extension
```
mvn clean package
```

2. Put the generated JAR to Keycloak's providers directory:
```
cp target/*.jar /path/to/keycloak/providers/
```

3. Restart Keycloak

## Configuration

1. Create or select an authentication flow.
2. Add an `External HTTP Authentication` step.
3. Set the `External service URL` setting and other parameters.

### Settings

* `External HTTP service URL` - URL of your service to which the POST request will be sent
* `External HTTP service call timeout (in ms)` - request timeout

## Payload

The extension sends a POST request with a JSON payload:

```
{
    'roles': ['role1', 'role2', ...],
    'attributes': {'myattribute': 'somevalue', 'username': 'user1', ...},
    'groups': ['group1', 'group2', ...]
}
```

## External service

The external service should respond:
* status code 200 to allow
* status code 401,403 to deny