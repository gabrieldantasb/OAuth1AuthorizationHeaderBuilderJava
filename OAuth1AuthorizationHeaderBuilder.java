import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.security.SecureRandom;

public class OAuth1AuthorizationHeaderBuilder {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();
    private static final Set<Character> UnreservedChars = new HashSet<>(Arrays.asList(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '-', '_', '.', '~'));

    public static String build (
            String consumerKey,
            String consumerSecret,
            String accessToken,
            String tokenSecret,
            String url,
            String method
    ) {

        Map<String, String> parameters = new LinkedHashMap<String, String>();

        parameters.put("oauth_consumer_key", consumerKey);
        parameters.put("oauth_token", accessToken);
        parameters.put("oauth_signature_method", "HMAC-SHA1");
        parameters.put("oauth_timestamp", "" + Instant.now().getEpochSecond());
        parameters.put("oauth_nonce", generateNonce());
        parameters.put("oauth_version", "1.0");




        String parameterString = parameters.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> encodeURIComponent(e.getKey()) + "=" + encodeURIComponent(e.getValue()))
                .collect(Collectors.joining("&"));

        String signatureBaseString = method.toUpperCase() + "&" + encodeURIComponent(url) + "&" + encodeURIComponent(parameterString);

        String signingKey = encodeURIComponent(consumerSecret) + "&" + (tokenSecret == null ? "" : encodeURIComponent(tokenSecret));

        String signature = generateSignature(signingKey, signatureBaseString);

        parameters.put("oauth_signature", signature);

        return "OAuth " + parameters.entrySet().stream()
                .map(e -> encodeURIComponent(e.getKey()) + "=\"" + encodeURIComponent(e.getValue()) + "\"")
                .collect(Collectors.joining(", "));
    }

    private static String generateSignature(String secret, String message) {
        try {
            byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
            byte[] result = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 15; i++) {
            stringBuilder.append(secureRandom.nextInt(10));
        }
        String randomNumber = stringBuilder.toString();
        return randomNumber;
    }

    private static String encodeURIComponent(String s) {
        StringBuilder o = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            if (isSafe(b)) {
                o.append((char) b);
            } else {
                o.append('%');
                o.append(HEX[((b & 0xF0) >> 4)]);
                o.append(HEX[((b & 0x0F))]);
            }
        }
        return o.toString();
    }

    private static boolean isSafe(byte b) {
        return UnreservedChars.contains((char) b);
    }
}
