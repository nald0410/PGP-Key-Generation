/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ph.sysprog.encrypt;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import static ph.sysprog.encrypt.PgpEncryption.Encryption;
import static ph.sysprog.encrypt.PgpEncryption.setEncryptedData;

/**
 *
 * @author ASSTPROGRAMMER
 */
public class Main {
    public static String user_, host_, pass_;
    public static int port_;

    public static void main(String[] arg) throws IOException, UnknownHostException, FileNotFoundException, PGPException, NoSuchProviderException {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        host_ = arg[0];
        user_ = arg[1];
        pass_ = arg[2];
        port_ = Integer.parseInt(arg[3]);

        String msg = host_ + "\t" + user_ + "\t" + pass_ + "\t" + port_;
        
        setEncryptedData(msg);
        Encryption();
    }
}
