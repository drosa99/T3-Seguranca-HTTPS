package drosa99;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;


public class Main {

    private static final BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    private static final BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);

    private static final BigInteger a = new BigInteger("89384540494091085456630009856882");


    private static final BigInteger B = new BigInteger("5E123A18DB70E53166FE8998C3D87C3D27366CC5B7959BF79416126EA4674B80FB4A48D8BCE072788F60E8848226E4E2DC2F980D5B845936212579E8CD8AC79369F1D7A78EA47306A238763768D560FCC98E45CB86B6F34F410AB393351EFC8E6EB86819ABCD20EF94132C87D129C862B5B34BD047E01FA8A6D3DEF7F7ADD1D0", 16);
    private static final int IV_LENGTH = 16;

    private static MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {


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
        System.out.println("senha: " + byteArrayToHexString(senha));


        // ! - ETAPA 2
        //mensagem recebida pelo professor
        byte[] msg = hexStringToByteArray("16B82288CA1CEC745FA5511D56B4A40DB751EE2E3F585D03736589B49B3CCB699D88F28E1A01D55F3498B19128BC8B4F8857DFC6E865343DD0CC202F051BA8162405067BA7933B66DBC3FD1E7C5687DFF12932FB6B183424E543277F261F5F988CBDBCC471EFF29722D75AC955366270A81009E887B0C7EB315EBF4B659460AB");

        //descriptograda a mensagem recebida
        String msgDecifrada = descriptografa(senha, msg);
        System.out.println("Mensagem decifrada: " + msgDecifrada);

        //conteudo da mensagem revertida que sera enviada
        String msgDecifradaRevertida = inverteString(msgDecifrada);
        System.out.println("Mensagem decifrada invertida: " + msgDecifradaRevertida);

        //criptografa a mensagem para devolver para o professor
        String mensagemEnviada = criptografaMensagem(senha, msgDecifradaRevertida);
        System.out.println("Mensagem enviada: " + mensagemEnviada);

        System.out.println("teste descriptografa mensagem enviada criptografada: " + descriptografa(senha, hexStringToByteArray(mensagemEnviada)));
    }

    private static String criptografaMensagem(byte[] senha, String msgDescriptografada) throws UnsupportedEncodingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        //geracao do novo IV para mensagem que sera enviada
        byte[] ivGerado = gerarIVAleatorio();
        //faz a criptografia do conteudo da mensagem a ser enviada
        byte[] conteudoMsg = encryptDecrypt(Cipher.ENCRYPT_MODE, senha, ivGerado, msgDescriptografada.getBytes());

        //cria o array da mensagem completa = [iv] + [conteudo criptografado]
        byte[] mensagemCompleta = new byte[ivGerado.length + conteudoMsg.length];

        //coloca o IV e o conteudo no byte[] da mensagem completa
        System.arraycopy(ivGerado, 0, mensagemCompleta, 0, ivGerado.length);
        System.arraycopy(conteudoMsg, 0, mensagemCompleta, ivGerado.length, conteudoMsg.length);

        //mensagem completa criptografada em hex
        return byteArrayToHexString(mensagemCompleta);
    }

    private static String descriptografa(byte[] senha, byte[] msg) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] iv = new byte[16];
        byte[] mensagem;
        //aqui popula o iv com os primeiros 128 bits da mensagem recebida
        System.arraycopy(msg, 0, iv, 0, iv.length);

        //aqui coloca o restante da mensagem, parte após o iv, no array mensagem, que contem o conteudo da msg recebida
        int size = msg.length - iv.length;
        mensagem = new byte[size];
        System.arraycopy(msg, iv.length, mensagem, 0, size);

        //faz a decriptografia da mensagem com o iv e a senha obtidos
        byte[] resultadoBytes = encryptDecrypt(Cipher.DECRYPT_MODE, senha, iv, mensagem);

        //conteudo da mensagem decifrada
        return new String(resultadoBytes, StandardCharsets.UTF_8);
    }

    private static byte[] gerarIVAleatorio() throws UnsupportedEncodingException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] initVectorBytes = new byte[IV_LENGTH / 2];
        secureRandom.nextBytes(initVectorBytes);
        String initVector = byteArrayToHexString(initVectorBytes);
        return initVector.getBytes("UTF-8");
    }

    private static String inverteString(String msgDecifrada) {
        StringBuilder input = new StringBuilder(msgDecifrada);
        return input.reverse().toString();
    }

    //FONTE: código disponibilizado pelo professor Avelino no moodle da disciplina
    private static String byteArrayToHexString(byte[] b) {
        StringBuffer sb = new StringBuffer(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString().toUpperCase();
    }

    //FONTE: código disponibilizado pelo professor Avelino no moodle da disciplina
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    //metodo para gerar hash de um array de bytes utilizando a biblioteca MessageDigest
    private static byte[] gerarHash(byte[] bloco) {
        return md.digest(bloco);
    }

    //FONTE: https://makeinjava.com/encrypt-decrypt-message-using-aes-128-cbc-java-example/
    private static byte[] encryptDecrypt(final int mode, final byte[] senha, final byte[] IV, final byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(senha, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(message);
    }
}
