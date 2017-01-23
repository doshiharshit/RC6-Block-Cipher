import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Scanner;

public class RC6 {
	static int r = 20, w=32;
	static int A,B,C,D;
	static int P32=0xb7e15163, Q32=0x9e3779b9;
	static int t = 2*r+4;
	static int S[];
	static int u = w/8;  

	private static int rotRight(int value, int shift)
	{
	return (value >>> shift) | (value << (32-shift));
	}
	
	private static int rotLeft(int value, int shift)
	{
	return (value << shift) | (value >>> (32-shift));
	}
	
	public static int[] KeySchedule(int key[], int r, int b){
	
		int u = w/8; // no. of bytes/word
		int c = b/u; // words
	
		/******* Generation of L *********/
		int [] L = new int[c];
		for(int i=0;i<c;i++)
		{L[i] = 0x00;}
	
		for (int i = 0, off = 0; i < c; i++){
		L[i] = ((key[off++] )) | ((key[off++] ) << 8)
				| ((key[off++] ) << 16) | ((key[off++] ) << 24);
		}
		
		/******* Generation of S *********/
		int[] S = new int[t];
		
		S[0] = P32;
		for(int i=1; i<t; i++){
			S[i] = S[i-1] + Q32; 
		}
		
		/******** Mixing *****/
		 A = 0;
		 B = 0;
		int k = 0, j = 0;
		
		int v = 3 * Math.max(L.length, S.length);
		for (int i = 0; i < v; i++) {
			A = S[k] = rotLeft((S[k] + A + B), 3);
			B = L[j] = rotLeft(L[j] + A + B, A + B);
			k = (k + 1) % S.length;
			j = (j + 1) % L.length;

		}
		return S;
}
		
	public static int rearrangeAfterEnc(int data){ 	// dataOutError
		int dataOUT = 0x00;
		
		for(int i=0;i<4;i++){
			//dataOUT = dataOUT + ( (int)((data << data.SIZE-8*(i+1)  >> 8*i) & ((long)(255*(Math.pow(256, (data.SIZE/8)-(i+1))))) )) ;
//			System.out.println(Integer.toHexString( data << data.SIZE-16 >> 8  & (255*256*256)));
//			System.out.println(Integer.toHexString( data << data.SIZE-24 >> 16 & (255*256)));
//			System.out.println(Integer.toHexString( data << data.SIZE-32 >> 24 & (255)));
			
			dataOUT = ((data>>24)&0xff) |((data<<8)&0xff0000) | ((data>>8)&0xff00) | ((data<<24)&0xff000000); 
		}
		return dataOUT;
	}
	
	public static int rearrangeBeforeDec(int data){ //dataut Error
		int dataOUT = (data << 24) >> 0;
		
//		System.out.println(Integer.toHexString( (data << 0 ) >> 24 & 0x000000ff) );
//		System.out.println(Integer.toHexString( (data << 8 ) >> 16 & 0x0000ff00) );
//		System.out.println(Integer.toHexString( (data << 16) >> 8  & 0x00ff0000) );
//		System.out.println(Integer.toHexString( (data << 24) >> 0  ) );
		
		
		for(int i=2;i<=4;i++){
			dataOUT = dataOUT + ( ( (data << 32-(8*i)) >> 8*(i-1) )  & (int)(255*(Math.pow(256, (4)-(i)))) ) ;
//			System.out.println(Integer.toHexString( data << data.SIZE-16 >> 8  & (255*256*256)));
//			System.out.println(Integer.toHexString( data << data.SIZE-24 >> 16 & (255*256)));
//			System.out.println(Integer.toHexString( data << data.SIZE-32 >> 24 & (255)));
		}
//		System.out.println(Integer.toHexString(dataOUT));
		return dataOUT;
	}

	
	public static int[] Encryption(int []pt, int S[], int r){ // Needs to return Cipher Text
		
		int ct[];
		B += S[0];
		D += S[1];
		
		for(int i=1; i<=r; i++)
		{
		t = rotLeft( B*(2*B+1), 5 );
		u = rotLeft( D*(2*D+1), 5 );
		A = rotLeft( (A^t), u ) + S[2*i];
		C = rotLeft( (C^u), t ) + S[2*i+1];
		t = A; A=B; B=C; C=D; D=t;
		}
		A += S[2*r+2];
		C += S[2*r+3];
		
	
		A = rearrangeAfterEnc(A);
		B = rearrangeAfterEnc(B);
		C = rearrangeAfterEnc(C);
		D = rearrangeAfterEnc(D);

		return new int[] { A, B, C, D };
		/// Needs Return 
	}
	
	public static int[] Decryption(int []ct, int S[], int r){ // Needs to return Plain Text
		int u = 4;
		C -= S[2*r+3];
		A -= S[2*r+2];
		for(int i=2*r+2; i>2; )
		{
			t = D; D = C; C = B; B = A; A = t;
			u = rotLeft( D*(2*D+1), 5 );
			t = rotLeft( B*(2*B+1), 5 );
			C = rotRight( C-S[--i], t ) ^ u;
			A = rotRight( A-S[--i], u ) ^ t;
		}
		D -= S[1];
		B -= S[0];
		
		A = rearrangeBeforeDec(A);
		B = rearrangeBeforeDec(B);
		C = rearrangeBeforeDec(C);
		D = rearrangeBeforeDec(D);
		
		return new int[] { A, B, C, D };
		///////Needs RETURN 
	}
	
	public static void main(String [] args) throws Exception{
	
	Scanner rd = new Scanner(new FileInputStream(args[0]));
	String header = rd.nextLine();
	
	
	/****** User Key ******/
	String userKey = rd.nextLine().replaceAll("\\s","");
	int b = (userKey.length()/2);
	
	int keyVal[] = new int[b];
	for(int i=0;i<userKey.length()/2;i++){
		keyVal[i] = Integer.parseInt( userKey.charAt(i*2) + "" , 16 );
		keyVal[i] = rotLeft( keyVal[i], 4);
		keyVal[i] = keyVal[i] + Integer.parseInt( userKey.charAt(i*2+1) + "", 16);
//		System.out.print(Integer.toHexString(keyVal[i]));
	}
//	System.out.println();
	
	int K[] = keyVal;
	S = KeySchedule(K,r, b);
	
	
	
	/****** PlainText ******/
	String plainText = rd.nextLine().replaceAll("\\s","");
	rd.close();
	int [] keyValInput = new int[plainText.length()/2];
	for(int i=0;i<plainText.length()/2;i++){
		keyValInput[i] = Integer.parseInt( plainText.charAt(i*2) + "" , 16 );
		keyValInput[i] = rotLeft( keyValInput[i], 4);		
		keyValInput[i] = keyValInput[i] + Integer.parseInt( plainText.charAt(i*2+1) + "", 16);
	}
	
		int length = keyValInput.length/4;
		A = 0x00;
		for(int i=0;i<length;i++){
			A = rotLeft(A, 8) + keyValInput[i];
		}
	
		B = 0x00;
		for(int i = length; i< ( length*2 );i++){
			B = rotLeft(B, 8) + keyValInput[i];
		}
	
		C = 0x00;
		for(int i= length*2;i<length*3;i++){
			C = rotLeft(C, 8) + keyValInput[i];
		}

		D = 0x00;
		for(int i=length*3;i<length*4;i++){
			D = rotLeft(D, 8) + keyValInput[i];
		}

		if(header.replaceAll(" ", "").startsWith("en")){
			int ct[] = Encryption(  K ,S, r);
			StringBuffer outStr = new StringBuffer("ciphertext:");
			for(int i=0;i<ct.length;i++){
				for(int j=0;j<7;j++){
					outStr.append( " ")
					.append( Integer.toHexString(ct[i]).substring(j, j+2) );
					j++;
				}
			}
			
			File outFile = new File(args[1]);
			FileOutputStream fout = new FileOutputStream(outFile);
			fout.write(outStr.toString().getBytes());
			fout.close();
//			System.out.println(outStr);
		}else{
			int ct[] = Decryption(  K ,S, r);
			StringBuffer outStr = new StringBuffer("plaintext:");
			for(int i=0;i<ct.length;i++){
				for(int j=0;j<7;j++){
					outStr.append( " ")
					.append( Integer.toHexString(ct[i]).substring(j, j+2) );
					j++;
				}
			}
			File outFile = new File(args[1]);
			FileOutputStream fout = new FileOutputStream(outFile);
			fout.write(outStr.toString().getBytes());
			fout.close();
//			System.out.println(outStr);
		}
	
	
}

}
