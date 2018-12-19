package br.com.jairsjunior.security.oauthbearer;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import scala.Int;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class OauthBearerTokenJwt implements OAuthBearerToken {

    private String value;
    private long lifetimeMs;
    private String principalName;
    private Long startTimeMs;
    private Set<String> scope;
    private long expirationTime;
    private String jti;

    private Set<String> publicFields;
    private Set<String> privateFields;

    public OauthBearerTokenJwt(String accessToken, long lifeTimeS, long startTimeMs, String principalName){
        super();
        this.value = accessToken;
        this.principalName= principalName;
        this.lifetimeMs = startTimeMs + (lifeTimeS * 1000);
        this.startTimeMs = startTimeMs;
        this.expirationTime = startTimeMs + (lifeTimeS * 1000);
    }

    public OauthBearerTokenJwt(Map<String, Object> jwtToken, String accessToken){
        super();
        this.value = accessToken;
        this.principalName = (String) jwtToken.get("sub");

        if(this.scope == null){
            this.scope = new TreeSet<>();
        }
        if(jwtToken.get("scope") instanceof String ){
            this.scope.add((String) jwtToken.get("scope"));
        }else if(jwtToken.get("scope") instanceof List){
            for(String s : (List<String>) jwtToken.get("scope")){
                this.scope.add(s);
            }
        }

        Object exp = jwtToken.get("exp");
        if(exp instanceof Integer){
            this.expirationTime = Integer.toUnsignedLong((Integer) jwtToken.get("exp")) ;
        }else{
            this.expirationTime = (Long) jwtToken.get("exp");
        }

        Object iat = jwtToken.get("iat");
        if(exp instanceof Integer){
            this.startTimeMs = Integer.toUnsignedLong((Integer) jwtToken.get("iat")) ;
        }else{
            this.startTimeMs = (Long) jwtToken.get("iat");
        }

        this.lifetimeMs = expirationTime;
        this.jti = (String) jwtToken.get("jti");
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Set<String> scope() {
        return scope;
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs != null ? startTimeMs : 0;
    }

    public long expirationTime(){
        return expirationTime;
    }

    public String jti(){
        return jti;
    }

    @Override
    public String toString() {
        return "OauthBearerTokenJwt{" +
                "value='" + value + '\'' +
                ", lifetimeMs=" + lifetimeMs +
                ", principalName='" + principalName + '\'' +
                ", startTimeMs=" + startTimeMs +
                ", scope=" + scope +
                ", expirationTime=" + expirationTime +
                ", jti='" + jti + '\'' +
                ", publicFields=" + publicFields +
                ", privateFields=" + privateFields +
                '}';
    }
}