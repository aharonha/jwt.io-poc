package io.jsonwebtoken;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.spec.SecretKeySpec;

public class Bootstrap {

  private static final String TENENT_ID = "tenentId";

  public static void main(String[] args) throws Exception {
    final CertificateFactory cf = CertificateFactory.getInstance("X.509");


    Map<String, byte[]> secretKeyStore = new HashMap<>();
    Properties properties = System.getProperties();
    String keystorePath = properties.getProperty("keystore.path");
    Properties keyFile = new Properties();
    try {
      keyFile.load(new FileReader(new File(keystorePath)));
      keyFile
          .forEach((Object key, Object value) -> secretKeyStore.put(String.valueOf(key),
              Base64.getDecoder().decode(String.valueOf(value))));
    } catch (Exception ignoredException) {
      throw ignoredException;
    }



    JwtParser parser = Jwts.parser();

    SigningKeyResolver signingSecretKeyResolver = new SigningKeyResolver() {

      public Key resolveSigningKey(JwsHeader<?> header) {
        SignatureAlgorithm alg = SignatureAlgorithm.forName(header.getAlgorithm());
        byte[] keyBytes = secretKeyStore.get(header.getKeyId());
        if (alg.isHmac()) {
          return new SecretKeySpec(keyBytes, alg.getJcaName());
        } else if (alg.isRsa()) {
          try {
            return cf.generateCertificate(new ByteArrayInputStream(keyBytes)).getPublicKey();
          } catch (CertificateException ignoredException) {
            return null;
          }
        } else if (alg.isEllipticCurve()) {
          return null;
        }
        throw new IllegalArgumentException("Unknown algorithm");
      }

      @Override
      public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return resolveSigningKey(header);
      }

      @Override
      public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return resolveSigningKey(header);
      }
    };

    secretKeyStore.keySet().forEach(System.out::println);

    for (String token : args) {
      Jws<Claims> jwt;
      try {
        jwt = parser.setSigningKeyResolver(signingSecretKeyResolver).parseClaimsJws(token);
        System.out.println(jwt);
      } catch (SignatureException ignoredException) {
        ignoredException.printStackTrace();
      }
    }
  }
}
