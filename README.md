# Kafka OAuth

## Client X Broker Authentication

### Container Environments
For client broker authentication, configure this environment variables:

- OAUTH_WITH_SSL: OAuth server with SSL. Example "false"
- OAUTH_ACCEPT_UNSECURE_SERVER: OAuth server with self-signed certificate. Example: "true"
- OAUTH_LOGIN_SERVER : Address of oauth server. Example: localhost:4444
- OAUTH_LOGIN_ENDPOINT : Login endpoint of OAuth server. Example: /oauth2/token
- OAUTH_LOGIN_GRANT_TYPE : Grant Type used at OAuth server. Example: client_credentials
- OAUTH_LOGIN_SCOPE : User scope. Example: producer.kafka
- OAUTH_AUTHORIZATION : Refresh token of client user. Example: Basic {TOKEN}

### Kafka Client Configuration (Producer/Consumer)

Add oauth-authorizer dependency in your `pom.xml` file

    <dependency>
        <groupId>jairsjunior</groupId>
        <artifactId>kafka-oauth</artifactId>
        <version>1.0.0</version>
    </dependency>

Add this properties in your kafka configuration

- sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;
- security.protocol=SASL_PLAINTEXT
- sasl.mechanism=OAUTHBEARER
- sasl.login.callback.handler.class=OauthAuthenticateLoginCallbackHandler

### Example (Producer/Consumer)

- https://github.com/jairsjunior/kafka-playground

## Broker X Broker Authentication

### Environments
For inter broker authentication, configure this environment variables:

- OAUTH_WITH_SSL: OAuth server with SSL. Example "false"
- OAUTH_ACCEPT_UNSECURE_SERVER: OAuth server with self-signed certificate. Example: "true"
- OAUTH_LOGIN_SERVER : Address of oauth server. Example: localhost:4444
- OAUTH_LOGIN_ENDPOINT : Login endpoint of OAuth server. Example: /oauth2/token
- OAUTH_LOGIN_GRANT_TYPE : Grant Type used at OAuth server. Example: client_credentials
- OAUTH_LOGIN_SCOPE : User scope. Example: broker.kafka
- OAUTH_AUTHORIZATION : Refresh token of client user. Example: Basic {TOKEN}
- OAUTH_INTROSPECT_SERVER : Address of oauth server. Example: localhost:4444
- OAUTH_INTROSPECT_ENDPOINT : Instrospect endpoint of oauth server. Example: /oauth2/introspect
- OAUTH_INTROSPECT_AUTHORIZATION : Refresh token of introspecter service. Example: Basic {TOKEN}

### Kafka Server Configuration

Add this properties in server.properties

- security.inter.broker.protocol=SASL_PLAINTEXT or (SASL_SSL)
- sasl.mechanism.inter.broker.protocol=OAUTHBEARER
- sasl.enabled.mechanisms=OAUTHBEARER
- listener.name.sasl_plaintext.oauthbearer.sasl.login.callback.handler.class=br.com.jairsjunior.security.oauthbearer.OauthAuthenticateLoginCallbackHandler
- listener.name.sasl_plaintext.oauthbearer.sasl.server.callback.handler.class=br.com.jairsjunior.security.oauthbearer.OauthAuthenticateValidatorCallbackHandler
- listeners=SASL_PLAINTEXT://:{PORT} or (SASL_SSL://:{PORT})
- advertised.listeners=SASL_PLAINTEXT://{HOST_IP}:{PORT} or (SASL_SSL://{HOST_IP}:{PORT})

### JAAS Security Configuration

1. Create an file called kafka_server_jaas.conf with this content:

    ```
    KafkaServer {
        org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required ;
    };
    ```
2. Add this file to config path of kafka.

3. Add `-Djava.security.auth.login.config=/opt/kafka/config/kafka_server_jaas.conf` at java args to load the configuration file.
    
