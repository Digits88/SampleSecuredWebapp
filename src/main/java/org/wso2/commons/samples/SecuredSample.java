package org.wso2.commons.samples;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.log4j.Logger;

import sun.misc.BASE64Encoder;

@WebServlet("/SecuredSample")
public class SecuredSample extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger log = Logger.getLogger(SecuredSample.class);
	private static String serviceURL = "http://localhost:9763/services/samples/JSONSample/";

	@Override
	public void init() throws ServletException {

	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		processRequest(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		processRequest(req, resp);
	}
	
	private void processRequest(HttpServletRequest req, HttpServletResponse resp) throws IOException{
		String cmd;
		String salary;
		
		cmd = req.getParameter("cmd");
		if (cmd == null || "get".equals(cmd)) {
			sendGETRequest(req, resp);
			return;
		}
		
		salary = (String) req.getParameter("sal");
		if (salary == null) {
			salary = "9999";
		}
		
		if ("update".equals(cmd)) {
			sendPUTRequest(req, resp, salary);
			return;
		}
	}

	private void sendGETRequest(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		PrintWriter out = resp.getWriter();
		KeyPair clientKeyPair;
		try {
			clientKeyPair = loadClientKeyPair();
			SignedJWT signedJWT = getSignedJWT(null, clientKeyPair.getPublic(),
					clientKeyPair.getPrivate());
			URL url = new URL(serviceURL + "employee/4001?tok="
					+ signedJWT.serialize());

			URLConnection connection = url.openConnection();
			connection.setRequestProperty("accept", "application/json");
			InputStream in = connection.getInputStream();

			String result = readPayload(in);

			log.info("Result : " + result);
			out.println(result);
		} catch (KeyStoreException e) {
			log.error("Error while loading client key pair", e);
		} catch (NoSuchAlgorithmException e) {
			log.error("No such method exception", e);
		} catch (CertificateException e) {
			log.error("Certificate exception", e);
		} catch (UnrecoverableEntryException e) {
			log.error("Unable to reacover entry", e);
		} catch (JOSEException e) {
			log.error("Error while signing the JWT", e);
		}
	}

	private void sendPUTRequest(HttpServletRequest req,
			HttpServletResponse resp, String salary) throws IOException {
		PrintWriter out = resp.getWriter();
		KeyPair clientKeyPair;
		String payload = "{\n" + "  \"_putemployee\": {\n"
				+ "    \"employeeNumber\" : \"4001\",\n"
				+ "    \"lastName\": \"Samith\",\n"
				+ "    \"firstName\": \"Will\",\n"
				+ "    \"email\": \"will@samith.com\",\n"
				+ "    \"salary\": \"" + salary + "\"\n" + "  }\n" + "}";
		try {
			clientKeyPair = loadClientKeyPair();
			SignedJWT signedJWT = getSignedJWT(payload,
					clientKeyPair.getPublic(), clientKeyPair.getPrivate());
			PublicKey serverPublicKey = getServerPublicKey();
			String encryptedJWT = getEncryptedJWT(signedJWT, serverPublicKey);
			HttpClient client = new HttpClient();
			PutMethod putMethod = new PutMethod(serviceURL + "employee/");
			RequestEntity entity = new StringRequestEntity(encryptedJWT,
					"application/jwt", "utf-8");
			putMethod.setRequestEntity(entity);

			int resultCode = client.executeMethod(putMethod);
			String result = readPayload(putMethod.getResponseBodyAsStream());

			out.println(result);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private PublicKey getServerPublicKey() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		String pwd = "mypkpassword";
		FileInputStream fileInputStream = null;
		fileInputStream = new FileInputStream(
				"/home/gayashan/wso2/devs/BOEING-X509/service_keystore.jks");
		keyStore.load(fileInputStream, pwd.toCharArray());
		fileInputStream.close();

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				pwd.toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry("servc1_cert", protectionParameter);
		Certificate certificate = privateKeyEntry.getCertificate();
		return certificate.getPublicKey();
	}

	private String getEncryptedJWT(SignedJWT signedJWT,
			PublicKey serverPublicKey) throws JOSEException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP,
				EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload(signedJWT);
		JWEObject jweObject = new JWEObject(jweHeader, payload);
		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) serverPublicKey));
		return jweObject.serialize();
	}

	private KeyPair loadClientKeyPair() throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		String pwd = "mykspwd";
		FileInputStream fileInputStream = null;
		fileInputStream = new FileInputStream(
				"/home/gayashan/wso2/devs/RESTSecurityHandler/src/main/resources/client-keystore.jks");
		keyStore.load(fileInputStream, pwd.toCharArray());
		fileInputStream.close();

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				pwd.toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry("client_1", protectionParameter);

		RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry
				.getCertificate().getPublicKey();
		RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry
				.getPrivateKey();

		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		return keyPair;
	}

	private SignedJWT getSignedJWT(String payload, PublicKey publicKey,
			PrivateKey privateKey) throws JOSEException {
		// claims generation
		JWTClaimsSet jwtClaims = new JWTClaimsSet();
		jwtClaims.setIssuer("test-user");
		jwtClaims.setSubject("WSO2");
		List<String> aud = new ArrayList<String>();
		jwtClaims.setAudience(aud);
		jwtClaims.setExpirationTime(new Date(
				new Date().getTime() + 1000 * 60 * 10));
		jwtClaims.setNotBeforeTime(new Date());
		jwtClaims.setIssueTime(new Date());
		jwtClaims.setJWTID(UUID.randomUUID().toString());
		if (payload != null) {
			jwtClaims.setClaim("payload", payload);
		}

		List<Base64> certChain = new LinkedList<Base64>();
		String encodedPubKey = new BASE64Encoder().encode(publicKey
				.getEncoded());
		Base64 base64 = new Base64(encodedPubKey);
		certChain.add(base64);

		// create JWS header
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertChain(certChain).build();

		log.info(jwtClaims.toJSONObject());
		
		// sign header + payload
		SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaims);

		JWSSigner jwsSigner = new RSASSASigner((RSAPrivateKey) privateKey);
		signedJWT.sign(jwsSigner);

		return signedJWT;
	}

	private String readPayload(InputStream inputStream) {
		BufferedReader bufferedReader;
		bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
		StringBuilder stringBuilder = new StringBuilder();
		String line;
		try {
			while ((line = bufferedReader.readLine()) != null) {
				stringBuilder.append(line.trim());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return stringBuilder.toString();
	}

}
