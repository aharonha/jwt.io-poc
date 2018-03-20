package io.jsonwebtoken;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

public class Bootstrap {

  private static final String TENENT_ID = "tenentId";

  public static void main(String[] args) throws Exception {

    String token = args[0];
    System.out.println(token);
//    String key = args[1];
//    System.out.println(key);

    Map<String,byte[] > keyStore = new HashMap<>();
    keyStore.put("abcd",  Base64.getDecoder().decode("BBBB"));
    keyStore.put("efgh",  Base64.getDecoder().decode("CCCC"));


    JwtParser parser = Jwts.parser();


    SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
      @Override
      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
        return keyStore.get(claims.get(TENENT_ID));
      }
    };
    
    
    
    Jws<Claims> jwt = parser.setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);
    System.out.println(jwt);
  }
}
