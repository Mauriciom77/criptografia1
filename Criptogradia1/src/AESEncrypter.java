
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jdk.internal.util.xml.impl.Input;

/**
 *
 * @author Mauricio
 */
public class AESEncrypter {

    public static final int IV_SIZE = 16;
    public static final int KEY_SIZE = 16;
    public static final int BUFFER_SIZE = 1024;
    private Cipher cifra;
    private SecretKey chave;
    private AlgorithmParameterSpec ivSpec;
    private byte[] buf = new byte[BUFFER_SIZE];
    private byte[] ivBytes = new byte[IV_SIZE];

    public AESEncrypter(SecretKey chave) throws Exception {
        this.cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        this.chave = chave;
    }

    public static SecretKeySpec lerChave(String nomeArquivo) throws Exception {
        byte bytesChave[] = new byte[KEY_SIZE];
        FileInputStream fis = new FileInputStream(nomeArquivo);
        fis.read(bytesChave);
        return new SecretKeySpec(bytesChave, "AES");
    }

    public static void criarChave(String nomeArquivo) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(KEY_SIZE * 8);
        SecretKey chave = kg.generateKey();
        FileOutputStream fos = new FileOutputStream(nomeArquivo);
        fos.write(chave.getEncoded());
        fos.close();
    }

    public void criptografar(InputStream in, OutputStream out) throws Exception {
        ivBytes = createRandBytes(IV_SIZE);
        out.write(ivBytes);
        ivSpec = new IvParameterSpec(ivBytes);
        cifra.init(Cipher.ENCRYPT_MODE, chave, ivSpec);
        CipherOutputStream cipherOut = new CipherOutputStream(out, cifra);
        int numLido = 0;
        while ((numLido = in.read(buf)) >= 0) {
            cipherOut.write(buf, 0, numLido);
        }
        cipherOut.close();
    }

    public static byte[] createRandBytes(int numBytes) throws
            NoSuchAlgorithmException {
        byte[] bytesBuffer = new byte[numBytes];
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.nextBytes(bytesBuffer);
        return bytesBuffer;
    }

    public void descriptografar(InputStream in, OutputStream out) throws Exception {
        in.read(ivBytes);
        ivSpec = new IvParameterSpec(ivBytes);
        cifra.init(Cipher.DECRYPT_MODE, chave, ivSpec);
        CipherInputStream cipherIn = new CipherInputStream(in, cifra);
        int numLido = 0;
        while ((numLido = cipherIn.read(buf)) >= 0) {
            out.write(buf, 0, numLido);
        }
        out.close();
    }

    public static void main(String[] args) throws Exception {
        String arquivoChave = "MinhaChave";
        criarChave(arquivoChave);
        SecretKeySpec keySpec = lerChave(arquivoChave);
        AESEncrypter aes = new AESEncrypter(keySpec);
        aes.criptografar(new FileInputStream("texto.txt"), new FileOutputStream("criptografado.txt"));
        aes.descriptografar(new FileInputStream("criptografado.txt"), new FileOutputStream("saida.txt"));
    }
}
