import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * <p>@author Jason Eaton
 * <br>Engineering Secure Software - COSC 4953-01
 * <br>4/11/20</p>
 * <div>
 * <h1>notes from the assignment</h1>
 * <p> Your task is to use the JCE to create a program that will either encrypt or decrypt a file using AES 256 in CBC mode based on the commands passed on the command line. Items in [square brackets] will need to be replaced with the appropriate values.</p>
 * <p>To encrypt:
 * <br>Eaton02.java -e [password] [inputfile] [outputfile]
 * <br>To decrypt:
 * <br>Eaton02.java -d [password] [inputfile] [outputfile]</p>
 * <p> You will encounter some challenges setting up Java to allow you to use a 256-bit key. This is part of the exercise. It can be overcome fairly easily, but odds are your default installation will not allow you to do it.</p>
 * <p> Submit a .java file, and please do not use packages. </p>
 * </div>
 * <div>
 * <h1>note to the professor</h1>
 * <p>I had plenty enough time to make it so that the salt and IV are stored in the encrypted file as raw bytes. The salt is 32 bytes, and the IV is 16 bytes, and they're appended to the end of the file in that order. Enjoy!</p>
 * </div>
 */

public class Eaton02 {
    public static void main(String[] args) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        if (args.length != 4 || !(args[0].equals("-e") || args[0].equals("-d"))) {
            System.err.println("Usage: Eaton02 [-d or -e] password inputfile outputfile");
            return;
        }

        String password = args[1];
        String inFileName = args[2];
        String outFileName = args[3];

        File inFile = new File(inFileName);
        File outFile = new File(outFileName);

        byte[] inBytes = Files.readAllBytes(Paths.get(inFile.getPath()));
        byte[] xxcrypted;

        if (args[0].equals("-e")) {

            System.out.printf("Encrypting file [%s].\n", inFileName);
            xxcrypted = encryptAndSalt(inBytes, password);
        } else {
            byte[] encrpyted = new byte[inBytes.length - 48];
            System.arraycopy(inBytes, 0, encrpyted, 0, inBytes.length - 48);
            byte[] salt = new byte[32];
            System.arraycopy(inBytes, inBytes.length - 48, salt, 0, 32);
            byte[] iv = new byte[16];
            System.arraycopy(inBytes, inBytes.length - 16, iv, 0, 16);

            System.out.printf("Decrypting file [%s].\n", inFileName);
            xxcrypted = decryptWithSalt(encrpyted, salt, iv, password);
        }

        Files.write(outFile.toPath(), xxcrypted);

        System.out.printf("Done! Output is located at [%s].\n", outFileName);
    }

    private static byte[] encryptAndSalt(byte[] message, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        return xxcrypt(message, null, null, password, true);
    }

    private static byte[] decryptWithSalt(byte[] message, byte[] salt, byte[] iv, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        return xxcrypt(message, salt, iv, password, false);
    }

    private static byte[] xxcrypt(byte[] message, byte[] salt, byte[] iv, String password, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        byte[] out;

        if (salt == null) {
            salt = randBytes(32);
        }

        if (iv == null) {
            iv = randBytes(16);
        }

        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        if (encrypt) {
            cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

            byte[] encrypted = cipher.doFinal(message);
            out = new byte[encrypted.length + salt.length + iv.length];

            System.arraycopy(encrypted, 0, out, 0, encrypted.length);
            System.arraycopy(salt, 0, out, encrypted.length, salt.length);
            System.arraycopy(iv, 0, out, encrypted.length + salt.length, iv.length);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, ivspec);

            out = cipher.doFinal(message);
        }

        return out;
    }

    public static byte[] randBytes(int length) {
        SecureRandom randInt = new SecureRandom();
        byte[] out = new byte[length];
        randInt.nextBytes(out);
        return out;
    }
}
