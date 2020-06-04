public class MainProgram {

    public static void main(String []args){

        String text = "karpyshyn";
        String keyword = "olha";

        byte[] key = keyword.getBytes();
        byte[] plainText = text.getBytes();
        System.out.println(new String(plainText));

        RC4 rc4 = new RC4(key);
        System.out.println("RC4 Algorithm: ");
        byte[] encrypted = rc4.encrypt(plainText);
        System.out.println("Encrypted: "+ new String(encrypted));

        rc4 = new RC4(key);
        byte[] decypted = rc4.decrypt(encrypted);
        System.out.println("Decrypted: "+ new String(decypted));

    }
}
