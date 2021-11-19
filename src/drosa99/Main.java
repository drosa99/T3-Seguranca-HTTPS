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


/**
 * Author: Daniela Amaral
 * Trabalho 3 da cadeira de Segurança de Sistemas PUCRS - 2021/2
 */
public class Main {

    /*
     * MSGS RECEBIDAS:
     * B = 5E123A18DB70E53166FE8998C3D87C3D27366CC5B7959BF79416126EA4674B80FB4A48D8BCE072788F60E8848226E4E2DC2F980D5B845936212579E8CD8AC79369F1D7A78EA47306A238763768D560FCC98E45CB86B6F34F410AB393351EFC8E6EB86819ABCD20EF94132C87D129C862B5B34BD047E01FA8A6D3DEF7F7ADD1D0
     * MSG = 16B82288CA1CEC745FA5511D56B4A40DB751EE2E3F585D03736589B49B3CCB699D88F28E1A01D55F3498B19128BC8B4F8857DFC6E865343DD0CC202F051BA8162405067BA7933B66DBC3FD1E7C5687DFF12932FB6B183424E543277F261F5F988CBDBCC471EFF29722D75AC955366270A81009E887B0C7EB315EBF4B659460AB
     * ULTIMA MSG = 3C0FDD347AFC68FDCC3E2B1E49E459D65DD10920D898DEAFB9E8AEC8A3A5F867F1BFDB26E7563867F24C0FDF4338ED4D9B10C7AFD024522AE961DE179A76D3870E82E64752CE92156E4E3327E18CC6B51FFFD7E3AFF0B9290C4F531F5F780BB57A59BFC1C1B4AF6CE2C1085DB21B5C1061621C5D15BF03BAB18E385E601C58AC7E679BD0255698B50ADAF6405AF840F8
     * */

    /*
     * MSGS ENVIADAS:
     * A = 10495a315c6eb69a5969293cdacb4bf5c818c39587c651faf2a42b4b05d288758572f91b4ce1993b0046ca0715274c2450e9ce646e17775a88c23f91a847f8bcdd3455643850ee8db3f474d3c96c3626ca3b166a6f7e18554f7dc1c1f382998bedc24fd5d0a33cd5688f346cc94a463f2100859045031714a0261dfc6f807dd4
     * MSG INVERTIDA = 314635454643303630444343464231362F8D985679DBBC07FF1128B653AD9073DEB91C8623147F851CBD96549E981DAA778CBE4B09CD7C29D4DFFB968CA66B4A486D790973E1CABD552E891EDB482DB292F3030620B54B2698C4536F68F99D449C55013F5006DC499C8902EBD0D95F51542B6FC328045628418C3740BCE9B174
     * */

    private static final BigInteger p = new BigInteger("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16);
    private static final BigInteger g = new BigInteger("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16);

    //aqui esta o "a" escolhido
    private static final BigInteger a = new BigInteger("89384540494091085456630009856882");


    private static final BigInteger B = new BigInteger("5E123A18DB70E53166FE8998C3D87C3D27366CC5B7959BF79416126EA4674B80FB4A48D8BCE072788F60E8848226E4E2DC2F980D5B845936212579E8CD8AC79369F1D7A78EA47306A238763768D560FCC98E45CB86B6F34F410AB393351EFC8E6EB86819ABCD20EF94132C87D129C862B5B34BD047E01FA8A6D3DEF7F7ADD1D0", 16);
    private static final int IV_LENGTH = 16;

    public static final String MSG_RECEBIDA = "16B82288CA1CEC745FA5511D56B4A40DB751EE2E3F585D03736589B49B3CCB699D88F28E1A01D55F3498B19128BC8B4F8857DFC6E865343DD0CC202F051BA8162405067BA7933B66DBC3FD1E7C5687DFF12932FB6B183424E543277F261F5F988CBDBCC471EFF29722D75AC955366270A81009E887B0C7EB315EBF4B659460AB";
    public static final String ULTIMA_MSG_RECEBIDA = "3C0FDD347AFC68FDCC3E2B1E49E459D65DD10920D898DEAFB9E8AEC8A3A5F867F1BFDB26E7563867F24C0FDF4338ED4D9B10C7AFD024522AE961DE179A76D3870E82E64752CE92156E4E3327E18CC6B51FFFD7E3AFF0B9290C4F531F5F780BB57A59BFC1C1B4AF6CE2C1085DB21B5C1061621C5D15BF03BAB18E385E601C58AC7E679BD0255698B50ADAF6405AF840F8";

    private static MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException {


        // - ETAPA 1
        System.out.println("a (hex): " + a.toString(16));

        // - PASSO 1
        // g ^ a mod p
        BigInteger A = g.modPow(a, p);
        System.out.println("A (hex): " + A.toString(16));


        // - PASSO 2
        // B ^ a mod p
        BigInteger V = B.modPow(a, p);
        System.out.println("V (hex): " + V.toString(16));

        // - PASSO 3
        //gero o S com SHA-256
        byte[] S = gerarHash(V.toByteArray());

        //a senha é os primeiros 128 bits da hash = 16 bytes
        byte[] senha = Arrays.copyOfRange(S, 0, 16);
        System.out.println("senha: " + byteArrayToHexString(senha));


        // - ETAPA 2
        //mensagem recebida pelo professor
        byte[] msg = hexStringToByteArray(MSG_RECEBIDA);

        //descriptograda a mensagem recebida
        String msgDecifrada = descriptografa(senha, msg);
        System.out.println("Mensagem decifrada: " + msgDecifrada);

        //conteudo da mensagem revertida que sera enviada
        String msgDecifradaRevertida = inverteString(msgDecifrada);
        System.out.println("Mensagem decifrada invertida: " + msgDecifradaRevertida);

        //criptografa a mensagem para devolver para o professor
        String mensagemEnviada = criptografa(senha, msgDecifradaRevertida);
        System.out.println("Mensagem enviada: " + mensagemEnviada);

        System.out.println("Ultima mensagem recebida: " + descriptografa(senha, hexStringToByteArray(ULTIMA_MSG_RECEBIDA)));

    }

    //metodo que recebe a senha, e o conteudo da mensagem em texto claro, retorna String hexadecimal com a mensagem completa criptografada
    private static String criptografa(byte[] senha, String msgDescriptografada) throws UnsupportedEncodingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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

    //metodo que recebe a senha, a mensagem completa recebida e retorna o conteudo da mensagem decifrada em texto claro
    private static String descriptografa(byte[] senha, byte[] msg) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] iv = new byte[16];
        byte[] mensagem;
        //aqui popula o iv com os primeiros 128 bits da mensagem recebida
        System.arraycopy(msg, 0, iv, 0, iv.length);

        //aqui coloca o restante da mensagem recebida, parte após o iv, no array mensagem, que contem o conteudo da msg recebida
        int size = msg.length - iv.length;
        mensagem = new byte[size];
        System.arraycopy(msg, iv.length, mensagem, 0, size);

        //faz a decriptografia da mensagem com o iv e a senha obtidos
        byte[] resultadoBytes = encryptDecrypt(Cipher.DECRYPT_MODE, senha, iv, mensagem);

        //conteudo da mensagem decifrada
        return new String(resultadoBytes, StandardCharsets.UTF_8);
    }

    //metodo responsavel por gerar um IV aleatorio
    private static byte[] gerarIVAleatorio() throws UnsupportedEncodingException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] initVectorBytes = new byte[IV_LENGTH / 2];
        secureRandom.nextBytes(initVectorBytes);
        String initVector = byteArrayToHexString(initVectorBytes);
        return initVector.getBytes("UTF-8");
    }

    //metodo que recebe uma string e retorna o conteudo dela invertido
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
    //metodo que faz a criptografia ou decriptografia de uma mensagem, recebendo senha, IV e conteudo da mensagem utulizando AES-CBC-PKCS5Padding
    private static byte[] encryptDecrypt(final int mode, final byte[] senha, final byte[] IV, final byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(senha, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(message);
    }
}
