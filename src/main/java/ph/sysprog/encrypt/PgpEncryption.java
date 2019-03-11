/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ph.sysprog.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import static ph.sysprog.encrypt.PublicKey.getPublicKey;

/**
 *
 * @author ASSTPROGRAMMER
 */
public class PgpEncryption {
    private static String newLine = "\n";
    private static String str_Encrypted;
    private static String msg;

    /**
     * decrypt the passed in message stream
     *
     * @param encrypted The message to be decrypted.
     * @param passPhrase Pass phrase (key)
     *
     * @return Clear text as a byte array. I18N considerations are not handled
     * by this routine
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    /**
     * Simple PGP encryptor between byte[].
     *
     * @param clearData The test to be encrypted
     * @param passPhrase The pass phrase (key). This method assumes that the key
     * is a simple pass phrase, and does not yet support RSA or more
     * sophisiticated keying.
     * @param fileName File name. This is used in the Literal Data Packet (tag
     * 11) which is really inly important if the data is to be related to a file
     * to be recovered later. Because this routine does not know the source of
     * the information, the caller can set something here for file name use that
     * will be carried. If this r outine is being used to encrypt SOAP MIME
     * bodies, for example, use the file name from the MIME type, if applicable.
     * Or anything else appropriate.
     *
     * @param armor
     *
     * @return encrypted data.
     * @exception IOException
     * @exception PGPException
     * @exception NoSuchProviderException
     */
    public static byte[] encrypt(byte[] clearData, PGPPublicKey encKey,
            String fileName, boolean withIntegrityCheck, boolean armor)
            throws IOException, PGPException, NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (fileName == null) {
            fileName = PGPLiteralData.CONSOLE;
        }

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final
        // destination
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option
        // later,
        // in which case we would pass in bOut.
        String encString = "";

        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY, encString, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
        );
        pOut.write(clearData);

        lData.close();
        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5)
                .setSecureRandom(new SecureRandom()).setProvider("BC"));
        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey));

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();

        out.close();

        return encOut.toByteArray();
    }

    private static PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for
        // encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }

    public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            // File is too large
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int) length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }

    public static void Encryption() throws IOException, PGPException, NoSuchProviderException {

//        Security.addProvider(new BouncyCastleProvider());
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        
        byte[] original = getDataToEncrypt().getBytes();
        System.out.println("Starting PGP test");

        InputStream pubKey = new ByteArrayInputStream(getPublicKey().getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = encrypt(original, readPublicKey(pubKey), null,
                true, true);

        str_Encrypted = new String(encrypted);

        System.out.println(newLine + "Encrypted Message: " + newLine + getEncryptedData());
        InputStream encData = new ByteArrayInputStream(encrypted);
        ByteArrayOutputStream outFile = new ByteArrayOutputStream();

        encData.close();
        outFile.close();
    }

    public static String getDataToEncrypt() throws MalformedURLException, IOException {
        return PgpEncryption.msg;
    }

    public static String getEncryptedData() {
        return PgpEncryption.str_Encrypted;
    }

    public static void setEncryptedData(String msg) {
        PgpEncryption.msg = msg;
    }
}
