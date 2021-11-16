package drosa99;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Main {

    private static final BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    private static final BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);

    //private static final BigInteger a = new BigInteger("89384540494091085456630009856882");
    private static final BigInteger a = new BigInteger("102");


    private static final BigInteger B = new BigInteger("5A0B1B5D5794404EADAE3BE9D3F72AF602FDB4F066C7B9AD39632FD581CDB4646759F25183209404D1241567F7F873F1A01FA40F33F285CF10375E923FD8C0A53FCB9C98058A5E0DF665C9D5A86058659C51F1CE7C4D68D1389110B9D7CD74DE0A2AB158F373A99F61923B6103AAA55966698417E38F5CE3B16B25404CEDCF10", 16);

    // ! - aqui nao esta considerando que é case sensitive, isso ta provocando o erro de nao conseguir decifrar
    private static final byte[] msg = new BigInteger("580D66D68E6DF45E969CCAB880925DDE4C2D4E5706B38B38DA434035FE9A18BC53BD34964B094CA7C66CAC2B80FB8FF93A3BC8613261E660F9148B61F3A33EB893B3994E2EDC34EC1135CDBE108803B155CEA5662B97714089CCD9A9F4DC21E2", 16).toByteArray();

    private static MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

        // ! - ETAPA 1
        System.out.println("p: " + p);

        System.out.println("g: " + g);

        // ? - PASSO 1
        // g ^ a mod p
        BigInteger A = g.modPow(a, p);
        System.out.println("A certo: " + A.toString(16));
        System.out.println("A zuado: " + gerarHexDeByteArray(A.toByteArray()));

        // ? - PASSO 2
        // g ^ a mod p
        BigInteger V = B.modPow(a, p);
        V.toString(16);
        System.out.println("V: " + gerarHexDeByteArray(V.toByteArray()));

        // ? - PASSO 3
        //gero o S com SHA-256
        byte[] S = gerarHash(V.toByteArray());
        System.out.println("S: " +  gerarHexDeByteArray(S));
        //a senha é os primeiros 128 bits da hash = 16 bytes
        byte[] senha = Arrays.copyOfRange(S, 0, 16);
        System.out.println("senha: " + gerarHexDeByteArray(senha));


        // ! - ETAPA 2
        byte[] iv = Arrays.copyOfRange(msg, 0, 16);
        System.out.println("iv: " + gerarHexDeByteArray(iv));
        byte[] mensagem = Arrays.copyOfRange(msg, 16, msg.length);
        ByteBuffer buf = ByteBuffer.allocate(msg.length);
        buf.put(mensagem);
        byte[] resultadoBytes = encryptDecrypt(Cipher.DECRYPT_MODE, senha, iv, buf.array());

        String msgDecifrada = new String(resultadoBytes, StandardCharsets.UTF_8);
        System.out.println("msgDecifrada" + msgDecifrada);

    }

    private static String gerarHexDeByteArray(byte[] resultadoBytes) {
        StringBuilder sb = new StringBuilder();
        //transforma o hash de array de bytes para hexadecimal
        for (int i = 0; i < resultadoBytes.length; i++) {
            sb.append(Integer.toString((resultadoBytes[i] & 0xff) + 0x100, 16).substring(1));

        }
        return sb.toString();
    }

    //metodo para gerar hash de um array de bytes utilizando a biblioteca MessageDigest
    private static byte[] gerarHash(byte[] bloco) {
        return md.digest(bloco);
    }

    private static byte[] encryptDecrypt(final int mode, final byte[] key, final byte[] IV, final byte[] message){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        try {
            cipher.init(mode, keySpec, ivSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        try {
            return cipher.doFinal(message);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
