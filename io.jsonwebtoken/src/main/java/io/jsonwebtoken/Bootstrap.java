package io.jsonwebtoken;

import java.io.File;
import java.io.FileReader;
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
import java.util.Properties;
import java.util.function.BiFunction;

public class Bootstrap {

  private static final String TENENT_ID = "tenentId";

  public static void main(String[] args) throws Exception {


    Map<String, byte[]> keyStore = new HashMap<>();
    Properties properties = System.getProperties();
    String keystorePath = properties.getProperty("keystore.path");
    Properties keyFile = new Properties();
    try {
      keyFile.load(new FileReader(new File(keystorePath)));
      keyFile
          .forEach((Object key, Object value) -> keyStore.put(String.valueOf(key), String.valueOf(value).getBytes()));
    } catch (Exception ignoredException) {
      throw ignoredException;
    }

    JwtParser parser = Jwts.parser();

    SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
      @Override
      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
        return keyStore.get(header.getKeyId());
      }

      @Override
      public byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
        return this.resolveSigningKeyBytes(header, (Claims) null);
      }
    };


    for (String token : args) {
      Jws<Claims> jwt = parser.setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);
      System.out.println(jwt);
    }
  }
}
