package com.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;

/**
 * This gist demonstrates how to authenticate using gamecenter
 * <p>
 * see https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/GameKit_Guide/Introduction/Introduction.html
 * and https://developer.apple.com/documentation/gamekit/gklocalplayer/1515407-generateidentityverificationsign
 */
public class GameCenterGist {

	/**
	 * this method demonstrates how to authenticate your app using gamecenter.
	 *
	 * @param now                the current time
	 *
	 * @param bundleID           the bundle id of your app
	 *                           -> call Bundle.main.bundleIdentifier in your app to get this
	 *
	 * @param gameCenterPlayerID the id of the local game center player
	 *                           -> call GKLocalPlayer.localPlayer.playerID in your iOS app to get this
	 *
	 * @param publicKeyURL       the url of the certificate needed to use in
	 *                           -> call GKLocalPlayer.localPlayer.generateIdentityVerificationSignature
	 *
	 * @param signature          the base64 encoded signature
	 *                           -> call GKLocalPlayer.localPlayer.generateIdentityVerificationSignature
	 *
	 * @param salt               the base 64 encoded salt
	 *                           -> call GKLocalPlayer.localPlayer.generateIdentityVerificationSignature
	 *
	 * @param timestamp          the timestamp the signature was issued
	 *                           -> call GKLocalPlayer.localPlayer.generateIdentityVerificationSignature
	 */
	public void authenticateGameCenter(
			final Instant now,
			final String bundleID,
			final String gameCenterPlayerID,
			final String publicKeyURL,
			final String signature,
			final String salt,
			final Long timestamp
	) {
		// Step 3. from the apple docs: Use the publicKeyURL on the third party server to download the public key.
		try (final CloseableHttpResponse response = HttpClients.createDefault().execute(new HttpGet(publicKeyURL))) {

			// Step 4. from the apple docs: Verify with the appropriate signing authority that the public key is signed by Apple.
			final byte[] certificateBytes = IOUtils.toByteArray(response.getEntity().getContent());

			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

			final KeyStore trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());

			// IMPORTANT: apple uses a Symatec Certificate which have been widely distrusted, which is why you might have to manually add Symantec to your truststore
			// This step should become obsolete once apple replaces the certificate with one that uses another trust authority
			// see https://www.thesslstore.com/blog/final-warning-last-chance-to-replace-symantec-ssl-certificates/
			// and https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
			trustAnchors.load(new FileInputStream(this.getClass().getResource("mykeystore.jks").getPath()), "changeit".toCharArray());

			final X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
			final CertPath certPath = certificateFactory.generateCertPath(Collections.singletonList(certificate));
			final CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			final PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);

			pkixParameters.setRevocationEnabled(false);

			final PKIXCertPathValidatorResult verificationResult = (PKIXCertPathValidatorResult)certPathValidator.validate(certPath, pkixParameters);

			certificate.verify(verificationResult.getTrustAnchor().getTrustedCert().getPublicKey());
			certificate.checkValidity(Date.from(now));

			// Step 6. from the apple docs: Concatenate into a data buffer the following information, in the order listed:
			//  - The playerID parameter in UTF-8 format
			//  - The bundleID parameter in UTF-8 format
			//  - The timestamp parameter in Big-Endian UInt-64 format
			//  - The salt parameter
			final ByteArrayOutputStream signatureDataToVerify = new ByteArrayOutputStream();
			final Charset utf8 = Charset.forName("UTF-8");
			final BaseEncoding base64 = BaseEncoding.base64();
			signatureDataToVerify.write(gameCenterPlayerID.getBytes(utf8));
			signatureDataToVerify.write(bundleID.getBytes(utf8));
			signatureDataToVerify.write(Longs.toByteArray(timestamp));
			signatureDataToVerify.write(base64.decode(salt));

			// Steps 7. and 8. from the apple docs: Using the public key downloaded in step 3, build the signature and verify the passed #signature
			final Signature calculatedSignature = Signature.getInstance("SHA256withRSA");
			calculatedSignature.initVerify(certificate.getPublicKey());
			calculatedSignature.update(signatureDataToVerify.toByteArray());

			if (calculatedSignature.verify(base64.decode(signature))) {
				System.err.println("authenticated");
			} else {
				System.err.println("not authenticated");
			}

		} catch (final Exception e) {
			System.err.println("not authenticated");
			e.printStackTrace();
		}
	}
}
