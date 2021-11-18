package drosa99;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main2 {
    public static byte[] S = new byte[16];
    public static byte[] IV = new byte[16];
    public static byte[] mensagem = null;;

    public static void main(String[] args) throws Exception {
        // SET DAS VARIAVEIS. HARCODED



        // definicao de a
        BigInteger a = new BigInteger("89384540494091085456630009856882");

        // mensagem a ser descriptografada
        String mensagemDoProfessor = "16B82288CA1CEC745FA5511D56B4A40DB751EE2E3F585D03736589B49B3CCB699D88F28E1A01D55F3498B19128BC8B4F8857DFC6E865343DD0CC202F051BA8162405067BA7933B66DBC3FD1E7C5687DFF12932FB6B183424E543277F261F5F988CBDBCC471EFF29722D75AC955366270A81009E887B0C7EB315EBF4B659460AB";


        // definicao de P (quebrado pra nao correr o risco de errar)
        String P = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6";
        P = P + "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0";
        P = P + "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70";
        P = P + "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0";
        P = P + "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708";
        P = P + "DF1FB2BC2E4A4371";
//
//        // Definicao de G (quebrado pra nao correr o risco de errar)
        String G = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F";
        G = G + "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213";
        G = G + "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1";
        G = G + "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A";
        G = G + "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24";
        G = G + "855E6EEB22B3B2E5";
//
//        // definicao de a
//        int a = 15;
//
//        // mensagem a ser descriptografada
//        String mensagemDoProfessor = "6A2BD0014CB208EEF38E2A3001ECFBC78E118A116D7920B7150D724736E6DAA5E9FA278582E9616DF5A5E4F311BB78E75601BC2E42F80F254901DD0909B6720EDC7A50DE0FEBFB758DC84181A87A0D4307F6C222B7E1084152763BA2233FE338AC5AA942F5D7FA873BC0CEF6E04A620B0E8B91A2E7DDF97C113BBC545459CD3ABD664421AA95C1AAF2A1A6CB653F50CF";

        // DESENVOLVIMENTO DO PROBLEMA
        System.out.println("///////////////////////////////////////");
        System.out.println("ETAPA 1");

        // PASSO 1 - calcula o A
        String A = passo1(G, a, P);

        // escreve o resultado (em hexa) em um TXT
        // (numero pode ser grande demais para o terminal/console printar)
        String nomeDoTxt = "resultDeA";
        System.out.println("Resultado de A em string:");
        gravaResult(A, nomeDoTxt);
        System.out.println();

        // valor de B recebido pelo professor
        String B = "5E123A18DB70E53166FE8998C3D87C3D27366CC5B7959BF79416126EA4674B80FB4A48D8BCE072788F60E8848226E4E2DC2F980D5B845936212579E8CD8AC79369F1D7A78EA47306A238763768D560FCC98E45CB86B6F34F410AB393351EFC8E6EB86819ABCD20EF94132C87D129C862B5B34BD047E01FA8A6D3DEF7F7ADD1D0";

        // PASSO 2 - calculo o V
        BigInteger V = passo2(B, a, P);

        // escreve o resultado (em hexa) em um TXT
        // (numero pode ser grande demais para o terminal/console printar)
        nomeDoTxt = "resultDeV";
        System.out.println("Resultado de V em string:");
        gravaResult(V.toString(), nomeDoTxt);
        System.out.println();

        // PASSO 3 - Calcula o S
        byte[] sCompleto = passo3(V);

        System.out.println("///////////////////////////////////////");
        System.out.println("ETAPA 2");

        // Receber uma mensagem do professor (em hexadecimal)
        // cifrada com o AES no modo de operação CBC, e padding
        // Formato da mensagem recebida: [128 bits com IV][mensagem] – em hexadecimal
        System.out.println("mensagemDoProfessor: " + mensagemDoProfessor);
        System.out.println();

        // separacao dos artefatos
        // obtem os valores para o cipher, obtem o S, o IV e MENSAGEM
        System.out.println("dados obtidos da separacao: ");
        separacao(mensagemDoProfessor, sCompleto);

        // Decifrar a mensagem (ja passando a mensagem em byte) e
        byte[] mensagemDescifrada = decifra();
        System.out.println("///////////////////////////////////////");
        System.out.println("TEXTO DESCIFRADO!!!");
        System.out.println("mensagem em texto: ");
        System.out.println(new String(mensagemDescifrada, StandardCharsets.UTF_8));
        System.out.println();

        // inverte ela
        // String novaMensagem = new String(mensagemDescifrada, StandardCharsets.UTF_8);
        String novaMensagem = new String(mensagemDescifrada, StandardCharsets.UTF_8);
        novaMensagem = invercao(novaMensagem);
        System.out.println("mensagem invertida: ");
        System.out.println(novaMensagem);
        System.out.println();

        // gera um novo IV aleatorio
        geraIv();

        // cifra ela para enviar
        byte[] novaMensagembytes = cifra(novaMensagem);
        System.out.println("mensagem criptografada em hex:");
        System.out.println(byteArrayToHexString(novaMensagembytes));
        System.out.println();

    }

    private static byte[] cifra(String mensagemParaCriptografar) {
        try {
            // IV
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
            // CHAVE
            SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
            // DEFINE O CIPHER
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // EXECUTA O CIPHER
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            // RETORNA DESCRIPTOGRAFADA
            byte[] mensagemCriptografada = cipher.doFinal(mensagemParaCriptografar.getBytes());
            // CONCATENA IV E A MENSAGEM CRIPTOGRAFADA
            byte[] mensagemConcatenada = new byte[IV.length + mensagemCriptografada.length];
            System.arraycopy(IV, 0, mensagemConcatenada, 0, IV.length);
            System.arraycopy(mensagemCriptografada, 0, mensagemConcatenada, IV.length, mensagemCriptografada.length);

            return mensagemConcatenada;
        } catch (Exception ex) {
            ex.printStackTrace();
            // Operation failed
        }
        return null;
    }

    private static void geraIv() {
        try {
            // metodo de geracao de IV recomendado no GIT
            // https://gist.github.com/demisang/716250080d77a7f65e66f4e813e5a636
            SecureRandom secureRandom = new SecureRandom();
            byte[] initVectorBytes = new byte[IV.length / 2];
            secureRandom.nextBytes(initVectorBytes);
            String initVector = byteArrayToHexString(initVectorBytes);
            initVectorBytes = initVector.getBytes("UTF-8");
            IV = initVectorBytes;

            System.out.println("novo IV gerado (de forma aleatoria)");
            System.out.println("IV (em hexa): " + initVector);
            System.out.println();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static String invercao(String mensagemParaInverter) {
        String reversed = "";
        for (int i = mensagemParaInverter.length() - 1; i >= 0; i--) {
            reversed = reversed + mensagemParaInverter.charAt(i);
        }
        return reversed;
    }

    private static byte[] decifra() {
        try {
            // IV
            IvParameterSpec iv = new IvParameterSpec(IV);
            // CHAVE
            // SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(S, "AES");
            // DEFINE O CIPHER
            // Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // EXECUTA O CIPHER
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            // RETORNA DESCRIPTOGRAFADA
            return cipher.doFinal(mensagem);
            // return cipher.doFinal(byteTexto);*/
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        // caso ocorrer algum erro
        return null;
    }

    private static void separacao(String mensagemDoProfessor, byte[] Scompleto) throws UnsupportedEncodingException {
        // PRIMEIRO: obtencao do S
        // pega os primeiros 128 bits do SHA para obter o S
        System.arraycopy(Scompleto, 0, S, 0, S.length);
        System.out.println("S em byte[]: ");
        for (int i = 0; i < S.length; i++) {
            System.out.print(S[i] + " ");
        }
        System.out.println();
        System.out.println("S em texto plano: " + new String(S, StandardCharsets.UTF_8));
        System.out.println("S em hexa: " + byteArrayToHexString(S));
        System.out.println("S em Base64: " + Base64.getEncoder().encodeToString(S));
        System.out.println();

        // de string (hex) para byte array
        BigInteger aux = new BigInteger(mensagemDoProfessor, 16);
        byte[] mensagemBytes = aux.toByteArray();

        // SEGUNDO: obtencao do IV
        // separa os primeiros 128 bits
        System.arraycopy(mensagemBytes, 0, IV, 0, IV.length);
        System.out.println("IV em texto plano: " + new String(IV, StandardCharsets.UTF_8));

        // TERCEIRO: obtencao da mensagem
        // bits apos os primeiros 128
        int size = mensagemBytes.length - IV.length;
        mensagem = new byte[size];
        System.arraycopy(mensagemBytes, IV.length, mensagem, 0, size);
        System.out.println("Mensagem em texto plano: " + new String(mensagem, StandardCharsets.UTF_8));
        System.out.println();
    }

    private static byte[] passo3(BigInteger v) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // Passo 3: calcular S = SHA256(V) e
        // usar os primeiros 128 bits como senha para se comunicar com o professor
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(v.toByteArray());
        return digest.digest();
    }

    private static BigInteger passo2(String B, BigInteger a, String P) {
        // Passo 2: receber um valor B (em hexadecimal) do professo
        // e calcular V = Ba mod p

        // de hexa para decimal
        BigInteger newB = new BigInteger(B, 16);
        BigInteger newP = new BigInteger(P, 16);

        // b elevado ao a
//        newB = newB.pow(a);
//
//        // resutlado mod de p
//        newB = newB.remainder(newP);

        // retorno do resultado
        return newB.modPow(a, newP);
    }

    private static String passo1(String G, BigInteger a, String P) {
        // Passo 1: gerar um valor a menor que p (dado) e calcular A = ga mod p.
        // Enviar o valor de A (em hexadecimal) para o professor.
        // de hexa para decimal
        BigInteger newG = new BigInteger(G, 16);
        BigInteger newP = new BigInteger(P, 16);

        // g elevado ao a
//        newG = newG.pow(a);
//
//        // resutlado mod de p
//        newG = newG.remainder(newP);

        // retorno do resultado
        //return newG.toString(16);
        return newG.modPow(a, newP).toString(16);
    }

    // metodo para gravar em um TXT
    private static void gravaResult(String texto, String nomeDoTxt) {
        System.out.println(texto);
        nomeDoTxt = nomeDoTxt + ".txt";
        try {
            FileWriter myWriter = new FileWriter(nomeDoTxt);
            myWriter.write(texto);
            myWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

    }

    // metodo para transformar um array de bytes em uma string, em hexadecimal
    public static String byteArrayToHexString(byte[] encrypted) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[encrypted.length * 2];
        int v;
        for (int j = 0; j < encrypted.length; j++) {
            v = encrypted[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}