package me.stec.jni.test;

import me.stec.jni.XCrypt;
import me.stec.jni.XCryptException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class Main {

	/**
	 * @param args
	 * @throws XCryptException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws XCryptException, IOException {
		File in = new File("text_in.txt");

		XCrypt xCrypt = new XCrypt(XCrypt.XCRY_EALGO_3FISH512);
		int szBlock = xCrypt.getBlockLen();
		byte[] inBytes = readBytesFromFile(in);
		byte[] tweak = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; 
		byte[] key = {	3, 4, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
						1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
		}; 
		
		/* encryption ... */
		xCrypt.setKey(key);
		
		xCrypt.setTweak(tweak);
		byte[] encryptedBytes = xCrypt.encrypt(inBytes);
		FileOutputStream fos = new FileOutputStream("text_out.txt");
		fos.write(encryptedBytes);
		
		/* decryption ... */
		xCrypt.setTweak(tweak);
		byte[] outBytes = new byte[inBytes.length];
		int offsetEnc = 0; /* to trace encryptedBytes */
		int offsetOut = 0;  /*to trace outBytes */
		int[] pOutDataType = new int[1];
		int[] pOutSzData = new int[1];
		int[] pOutNdxDataStart = new int[1];
		while(offsetOut < outBytes.length){
			byte[] pHead = Arrays.copyOfRange(encryptedBytes, offsetEnc, offsetEnc + szBlock);
			offsetEnc += szBlock;
			pHead = xCrypt.decryptHead(pHead, pOutDataType, pOutSzData, pOutNdxDataStart);
			if(null != pHead){ // (pOutNdxDataStart[0] < szBlock) is equivalent condition
				System.arraycopy(pHead, 0, outBytes, offsetOut, pHead.length);
				offsetOut += pHead.length;
			}
			if(pOutSzData[0] > szBlock){
				byte[] pTail = new byte[pOutSzData[0] - szBlock];
				System.arraycopy(encryptedBytes, offsetEnc, pTail, 0, pTail.length);
				offsetEnc += pTail.length;
				pTail = xCrypt.decryptTail(pTail);
				if(pOutNdxDataStart[0] <= szBlock){ // copy whole decrypted tail
					System.arraycopy(pTail, 0, outBytes, offsetOut, pTail.length);
					offsetOut += pTail.length;
				}
				else{
					System.arraycopy(pTail, pOutNdxDataStart[0] - szBlock, 
							outBytes, offsetOut, pTail.length - (pOutNdxDataStart[0] - szBlock));
					offsetOut += pTail.length - (pOutNdxDataStart[0] - szBlock);
				}
			}
		}
		boolean bArraysAreEqual = Arrays.equals(outBytes, inBytes); 
		assert(bArraysAreEqual);
		fos = new FileOutputStream("text_out_in.txt");
		fos.write(outBytes);
		xCrypt.Close();
		System.exit(0);
	}

	
	public static byte[] readBytesFromFile(File file) throws IOException {
	byte[] bytes = null;
	InputStream is = new FileInputStream(file);
	long length = file.length();
	if(length > Integer.MAX_VALUE) throw new IOException("Big file");
	int offset = 0;
	try{
		int numRead = 0;
		bytes = new byte[(int)length]; 
		// Read in the bytes
		while ( offset < bytes.length && 0 <= ( numRead = is.read(bytes, offset, bytes.length - offset) ) ) 
			offset += numRead;
	       
		// Ensure all the bytes have been read in
		if ( offset < bytes.length ) {
			throw new IOException("Could not completely read file " + file.getName() 
					+ " offset == " + offset + " startPos == " + 0 + " bytes.length == " + bytes.length);
		}
	}finally{
		// Close the input stream and return bytes
		is.close();
	}
	return bytes;
}
	
}
