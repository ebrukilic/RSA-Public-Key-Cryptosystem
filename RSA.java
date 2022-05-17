import java.math.BigInteger;
import java.util.Random;

public class RSA {

   static int bits = 1024;

   public static void main(String[] str) throws java.io.IOException {
   
      Random rndm = new Random();
      System.out.println("\nPublic key (N,e) and private key (N,d):");
      
      System.out.print("p value is  ");
      System.out.flush();
      BigInteger p = new BigInteger(bits/2, 50, rndm);
      System.out.println(p);
      
      System.out.print("q value is  ");
      System.out.flush();
      BigInteger q = new BigInteger(bits/2, 50, rndm);
      System.out.println(q);
      
      BigInteger N = p.multiply(q); //N value
      System.out.print("N = pq is       ");
      System.out.println(N);
      
      BigInteger p1 = p.subtract(new BigInteger("1")); // p-1
      BigInteger q1 = q.subtract(new BigInteger("1")); // q-1
      
      BigInteger p1q1 = p1.multiply(q1);  // (p-1)*(q-1)
      System.out.println("(p-1)(q-1) is   " + p1q1);
      System.out.println();
      
      // Choose numbers e and d such that e is prime and ed = 1 mod N.
      
      // choosing publicKey between 20 and 500 randomly.
      int min = 20;  
      int max = 500;  
		
      int publicKey = (int)(Math.random()*(max-min+1)+min);
      
      //control if they are relatively prime numbers
      while (true) {
			BigInteger BigB_GCD = p1q1.gcd(new BigInteger (""+ publicKey));
		
		if (BigB_GCD.equals (BigInteger.ONE)) {
				break;
		}
		
		publicKey++;
	}

       BigInteger pubKey = new BigInteger (""+ publicKey);
       BigInteger prvKey = pubKey.modInverse(p1q1);
		
       System.out.println("public key : " + pubKey+ " , "+N);
       System.out.println("private key: " + prvKey+ " , "+N);
      
      System.out.print("d value is ");
      System.out.println(prvKey);
      
      
      //Public key (N,d) and private key (N,e) has completed.
      //Now, do some encryptions and decryptions.
      
      while (true) {
         System.out.println("\n\n");
         System.out.println("Enter the plaintext, after that press enter: ");
         System.out.print("     ");
         StringBuffer buffer = new StringBuffer();
         
         while (true) {
            int ch = System.in.read();
            if (ch == '\n' || ch == -1)
               break;
            buffer.append((char)ch);
         }
         
         String st = buffer.toString();
         if (0 == st.trim().length())
            break;
         
         BigInteger[] cypher = encrypt(st,N,prvKey);
         System.out.println();
         
         System.out.println("RSA computed Encoded Text: ");
         for (int m = 0; cypher.length > m; m = m + 1)
            System.out.println("     " + cypher[m]);
         String plain = decrypt(cypher,N,pubKey);
         System.out.println();
         
         System.out.println("RSA computed Decoded Text: ");
         System.out.println("     " + plain);
      }
      System.out.println();
   }
   

   /**
    *  Converting the string to a BigInteger.  
    *  String should be consist of ASCII characters only.  
    */
   public static BigInteger stringToint(String str) {
      byte[] by = new byte[str.length()];
      for (int m = 0; by.length > m; m = m + 1)
         by[m] = (byte)str.charAt(m);
      
      return new BigInteger(1,by);
   }
   
   
   /**
    *  Converting the BigInteger to the string of ASCII characters.  
    *  Each byte in the integer is simply converted into the corresponding ASCII code.
    */
   public static String intTostring(BigInteger n) {
      byte[] by = n.toByteArray();
      StringBuffer st = new StringBuffer();
      for (int m = 0; m < by.length; m++)
         st.append((char)by[m]);
      return st.toString();
   }
   
   /**
    * By using the key (N,d).
    */
   public static String decrypt(BigInteger[] cypher, BigInteger N, BigInteger prvKey) {
      String st = "";
      for (int m = 0; cypher.length > m; m = m + 1)
         st += intTostring(cypher[m].modPow(prvKey,N));
      return st;
   }
   

   /**
    * By using the key (N,e), the string crumbled to chunks
    * Every chunk have converted into integer
    */
   public static BigInteger[] encrypt(String plain, BigInteger N, BigInteger pubKey) {
       int chchunk = (N.bitLength()-1);
       chchunk = chchunk/8;
       
       while (plain.length() % chchunk != 0)
           plain += ' ';
       
       int chu = plain.length()/ chchunk;
       BigInteger[] cp = new BigInteger[chu];
       for (int m = 0; m < chu; m++) {
          String st = plain.substring(chchunk*m,chchunk*(m + 1));
          cp[m] = stringToint(st);
          cp[m] = cp[m].modPow(pubKey,N);
       }
       return cp;
   }

}