package drosa99;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


public class Main {

    private static final BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    private static final BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);

    private static final BigInteger a = new BigInteger("89384540494091085456630009856882");
    //private static final BigInteger a = new BigInteger("102");


    private static final BigInteger B = new BigInteger("5E123A18DB70E53166FE8998C3D87C3D27366CC5B7959BF79416126EA4674B80FB4A48D8BCE072788F60E8848226E4E2DC2F980D5B845936212579E8CD8AC79369F1D7A78EA47306A238763768D560FCC98E45CB86B6F34F410AB393351EFC8E6EB86819ABCD20EF94132C87D129C862B5B34BD047E01FA8A6D3DEF7F7ADD1D0", 16);

    // ! - aqui nao esta considerando que é case sensitive, isso ta provocando o erro de nao conseguir decifrar
    private static final byte[] msg = HexToString.hexStringToByteArray("16B82288CA1CEC745FA5511D56B4A40DB751EE2E3F585D03736589B49B3CCB699D88F28E1A01D55F3498B19128BC8B4F8857DFC6E865343DD0CC202F051BA8162405067BA7933B66DBC3FD1E7C5687DFF12932FB6B183424E543277F261F5F988CBDBCC471EFF29722D75AC955366270A81009E887B0C7EB315EBF4B659460AB");

    private static byte[] iv = new byte[16];

    private static byte[] mensagem;

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
        System.out.println("a (hex): " + a.toString(16));

        // ? - PASSO 1
        // g ^ a mod p
        BigInteger A = g.modPow(a, p);
        System.out.println("A (hex): " + A.toString(16));


        // ? - PASSO 2
        // B ^ a mod p
        BigInteger V = B.modPow(a, p);
        System.out.println("V (hex): " + V.toString(16));

        // ? - PASSO 3
        //gero o S com SHA-256
        byte[] S = gerarHash(V.toByteArray());
        //System.out.println("S: " +  gerarHexDeByteArray(S));
        //a senha é os primeiros 128 bits da hash = 16 bytes
        byte[] senha = Arrays.copyOfRange(S, 0, 16);
        System.out.println("senha: " + gerarHexDeByteArray(senha));


        // ! - ETAPA 2
        //aqui popula o iv com os primeiros 128 bits da mensagem recebida
        System.arraycopy(msg, 0, iv, 0, iv.length);
        //System.out.println("iv: " + gerarHexDeByteArray(iv));

        //aqui coloca o restante da mensagem, parte após o iv, no array mensagem, que contem o conteudo da msg recebida
        int size = msg.length - iv.length;
        mensagem = new byte[size];
        System.arraycopy(msg, iv.length, mensagem, 0, size);

        //faz a decriptografia da mensagem com o iv e a senha obtidos
        byte[] resultadoBytes = encryptDecrypt(Cipher.DECRYPT_MODE, senha, iv, mensagem);

        //conteudo da mensagem decifrada
        String msgDecifrada = new String(resultadoBytes, StandardCharsets.UTF_8);
        System.out.println("Mensagem decifrada: " + msgDecifrada);

        //conteudo da mensagem revertida que sera enviada
        String msgDecifradaRevertida = inverteString(msgDecifrada);
        System.out.println("Mensagem decifrada invertida: " + msgDecifradaRevertida);

        //geracao do novo IV para mensagem que sera enviada
        byte[] ivGerado = gerarIVAleatorio();

        //faz a criptografia do conteudo da mensagem a ser enviada
        byte[] conteudoNovaMsg = encryptDecrypt(Cipher.ENCRYPT_MODE, senha, ivGerado, msgDecifradaRevertida.getBytes());

        //cria o array da mensagem completa = [iv] + [conteudo criptografado]
        byte[] mensagemCompleta = new byte[ivGerado.length + conteudoNovaMsg.length];

        //coloca o IV e o conteudo no byte[] da mensagem completa
        System.arraycopy(ivGerado, 0, mensagemCompleta, 0, ivGerado.length);
        System.arraycopy(conteudoNovaMsg, 0, mensagemCompleta, ivGerado.length, conteudoNovaMsg.length);

        //mensagem completa criptografada em hex
        String mensagemEnviada = HexToString.byteArrayToHexString(mensagemCompleta);
        System.out.println("Mensagem enviada: " + mensagemEnviada);


        //TODO enviar para o sor
        //463835383644374141444343383741328515BBD32C67E64D2689739C44D42DEAF2E8FE6E80B3BE3653BE884CEB642891DD83F0E7C2D72323D582015F6782DC6CDE0AF54CA6B611CF1375D70B442FA15E951DB2BBC0414EEC9E8F80656BCE70752782D5B559E3BF167278788B245271A38272CA3F838189E7A9F8087D52D46B95


    }

    private static byte[] gerarIVAleatorio() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] initVectorBytes = new byte[iv.length / 2];
        secureRandom.nextBytes(initVectorBytes);
        String initVector = HexToString.byteArrayToHexString(initVectorBytes);
        try {
            return initVector.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String inverteString(String msgDecifrada) {
        StringBuilder input = new StringBuilder(msgDecifrada);
        return input.reverse().toString();
    }

    private static String gerarHexDeByteArray(byte[] resultadoBytes) {
        StringBuilder sb = new StringBuilder();
        //transforma o hash de array de bytes para hexadecimal
        for (int i = 0; i < resultadoBytes.length; i++) {
            sb.append(Integer.toString((resultadoBytes[i] & 0xff) + 0x100, 16).substring(1));

        }
        return sb.toString();
    }

    //https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    //metodo para gerar hash de um array de bytes utilizando a biblioteca MessageDigest
    private static byte[] gerarHash(byte[] bloco) {
        return md.digest(bloco);
    }

    private static byte[] encryptDecrypt(final int mode, final byte[] senha, final byte[] IV, final byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(senha, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(mode, keySpec, ivSpec);
            return cipher.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
