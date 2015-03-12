package me.stec.jni;

import java.io.*;
import java.util.*;
class XCrypt {
		
  public static final int XCRY_EALGO_3FISH256   = 0;
  public static final int XCRY_EALGO_3FISH512   = 1;
  public static final int XCRY_EALGO_3FISH1024  = 2;
		


  private native int xcry_cipher_get_algo_keylen(int eAlgo);
  private native int xcry_cipher_get_algo_blklen(int eAlgo);


  private native String xcry_error(int XCRY_CODE); /* XCRY_CODE == code returned by xcry_open, xcry_close ...; if 0 == XCRY_CODE, everything is 0k. */
	
  private native void xcry_ini();

  private native int xcry_open(int[] pFd, int eAlgo);
  private native int xcry_close(int fd);

		
  private native int xcry_settwk(int fd, byte[] pTweak);
  private native int xcry_gettwk(int fd, byte[] pTweak);

		
  private native int xcry_setkey(int fd, byte[] pKey);

		
  private native int xcry_encrypt(int fd, byte[] pInBuf, byte[] pOutBuf);
  private native int xcry_decrypt(int fd, byte[] pInBuf, byte[] pOutBuf);

  /** in c xcry_data_prepare place the following XCryHead structure before the pInBuf and returns the XCryHead + pInBuf as ppOutBuf[0] in java
      struct XCryHead{
        u16   szData;
        u8    dataType;
        u8    szAlignLen;
        u16   chkSum;
        u16   randNum;
      };
    */
		
  public static final int XCRY_EDATA_TYPE_DATA = 0;
		
  /** pInBuf: max len == 2^16 - 1 - szBlock; pOutBuf: max len == 2^16 - 1 */
  private native int xcry_data_prepare(int eDataType, int szBlock, byte[] pInBuf, byte[] pOutBuf, int[] pSzOutBuf);
  private native int xcry_data_check_first_block(byte[] pInBuf, int szBlock);
  private native int xcry_data_metainfo(byte[] pInDecryptedBlock, int[] pOutDataType, int[] pOutSzData, int[] pOutNdxDataStart);

  public XCrypt(){ xcry_ini(); }

  private final static int SZ_BUF_MAX = 65535;
  public static byte[] readBytesFromFile(File file, int[] startPos, int blklen, int len) throws IOException {
    if(-1 == startPos[0]) return null;
    byte[] bytes = null;
    InputStream is = new FileInputStream(file);
    long length = file.length();
    int offset = startPos[0];
    try{ 
        if(0 == length || length <= offset ) return null;
        int numRead = 0;
        int szMax = SZ_BUF_MAX - blklen;
        int szBuf = ( -1 == len || len > szMax ) ? szMax : len;
        bytes = ( szBuf < (length  - offset) ) ? new byte[szBuf] : new byte[(int)(length - offset)]; 
   	    // Read in the bytes
        while ( offset < bytes.length && 0 <= ( numRead = is.read(bytes, offset, bytes.length - offset) ) ) 
            offset += numRead;
       
   	    // Ensure all the bytes have been read in
        if ( (offset - startPos[0]) < bytes.length ) {
            throw new IOException("Could not completely read file " + file.getName() 
            	    + " offset == " + offset + " startPos == " + startPos[0] + " bytes.length == " + bytes.length);
            }
    }finally{
	  // Close the input stream and return bytes
        is.close();
				}
    if( length <= offset ) startPos[0] = -1; // EOF
    else startPos[0] = offset;
    return bytes;
  }
  public static boolean writeBytesToFile(File file, int[] startPos, int len, byte[] bytes) throws IOException {
    if(-1 == startPos[0] || len <= 0 ) return false;
    OutputStream os = new FileOutputStream(file);
    try{
        os.write(bytes, startPos[0], len);
    }finally{
        os.close();
    }
    return true;
  }

		
  public static void main(String[] args) throws IOException {
    XCrypt p = null;
    int fd = -1;
    try {
        p = new XCrypt();
        int eAlgo = XCRY_EALGO_3FISH256;
        int eDataType = XCRY_EDATA_TYPE_DATA;
        int keylen = p.xcry_cipher_get_algo_keylen( eAlgo );
        int blklen = p.xcry_cipher_get_algo_blklen( eAlgo );
        byte[] pTwk = "abcdefghijklmno ".getBytes(); pTwk[pTwk.length - 1] = 0;
        byte[] pKey = "abcdefghijklmnopgergegwxyz12345 ".getBytes();  pKey[pKey.length - 1] = 0;
        int res;
        int[] pFd = new int[]{-1};
        if(0 != ( res = p.xcry_open(pFd, eAlgo) ) ){ System.out.println("p.xcry_open: " + p.xcry_error(res)); return; }
          fd = pFd[0];
          if(0 != ( res = p.xcry_settwk(pFd[0], pTwk) ) ){ System.out.println("p.xcry_settwk: " + p.xcry_error(res)); return; }
          if(0 != ( res = p.xcry_setkey(pFd[0], pKey) ) ){ System.out.println("p.xcry_setkey: " + p.xcry_error(res)); return; }
          File in = new File("text_in.txt");
          File out = new File("text_out.txt");
          int[] inPos = new int[]{ 0 }, outPos = new int[]{ 0 };
          byte[] bytes = null;
          while( null != ( bytes = readBytesFromFile(in, inPos, blklen, -1) ) ){
            byte[] outBytes = new byte[bytes.length + blklen];
            int[] pSzOutBuf = new int[]{ 0 };
            if( 0 != ( res = p.xcry_data_prepare(eDataType, blklen, bytes, outBytes, pSzOutBuf) ) ){
                System.out.println("p.xcry_data_prepare: " + p.xcry_error(res)); return;
            }
            byte[] pInDecryptedBlock = Arrays.copyOfRange(outBytes, 0, blklen);
            int[] pOutDataType = new int[]{ 0 }, pOutSzData = new int[]{ 0 }, pOutNdxDataStart = new int[]{ 0 };
            if( 0 != ( res = p.xcry_data_metainfo(pInDecryptedBlock, pOutDataType, pOutSzData, pOutNdxDataStart) ) ){
                System.out.println("xcry_data_metainfo: " + p.xcry_error(res)); return;
            }
            outBytes = Arrays.copyOfRange(outBytes, 0, pSzOutBuf[0]); //Arrays.copyOf(outBytes, pSzOutBuf[0]);
            byte[] pOutBuf = new byte[outBytes.length];
            if( 0 != ( res = p.xcry_encrypt(fd, outBytes, pOutBuf) ) ){ System.out.println("p.xcry_encrypt: " + p.xcry_error(res)); return; }
            //int xcry_data_prepare(int eDataType, int szBlock, byte[] pInBuf, byte[] pOutBuf, int[] pSzOutBuf);
            //int xcry_encrypt(int fd, byte[] pInBuf, byte[] pOutBuf);
            writeBytesToFile(out, outPos, pOutBuf.length, pOutBuf);
          }
/*          if(0 != ( res = p.xcry_settwk(fd, pTwk) ) ){ System.out.println("p.xcry_settwk: " + p.xcry_error(res)); return; }
						System.out.println("pTwk == " + new String(pTwk));
						in = new File("./text_out.txt");
						out = new File("./text_out_in.txt");	
						inPos[0] = 0; outPos[0] = 0;
						int[] pOutDataType = new int[]{ 0 }, pOutSzData = new int[]{ 0 }, pOutNdxDataStart = new int[]{ 0 };
						while( null != ( bytes = readBytesFromFile(in, inPos,  blklen, blklen ) ) ){  System.out.println("inPos[0] == " + inPos[0]);
							 byte[] outBytes = new byte[bytes.length];
							if( 0 != ( res = p.xcry_decrypt(fd, bytes, outBytes) ) ){ System.out.println("p.xcry_decrypt: " + p.xcry_error(res)); return; }
							if( 0 != ( res = p.xcry_data_check_first_block(outBytes, outBytes.length) ) ){ 
								System.out.println("p.xcry_data_check_first_block: " + p.xcry_error(res)); return; }
							writeBytesToFile(out, outPos, bytes.length, bytes);
							//int xcry_data_metainfo(byte[] pInDecryptedBlock, int[] pOutDataType, int[] pOutSzData, int[] pOutNdxDataStart);
							pOutDataType[0] = 0; pOutSzData[0] = 0; pOutNdxDataStart[0] = 0;
							if(0 != ( res = p.xcry_data_metainfo(outBytes, pOutDataType, pOutSzData, pOutNdxDataStart) ) ){
								System.out.println("p.xcry_data_metainfo: " + p.xcry_error(res)); return; }
							
							System.out.println("pOutDataType == " + pOutDataType[0] + " pOutSzData == " + pOutSzData[0] + " pOutNdxDataStart ==  " + pOutNdxDataStart[0]);		
							if(pOutNdxDataStart[0] < outBytes.length){System.out.println("pOutNdxDataStart[0] < outBytes.length");
               System.out.println("outBytes.length == " + outBytes.length + " bytes == " + new String(outBytes));
								outBytes = Arrays.copyOfRange(outBytes, pOutNdxDataStart[0], outBytes.length );
               System.out.println("outBytes.length == " + outBytes.length + " bytes == " + new String(outBytes));
								writeBytesToFile(out, outPos, outBytes.length, outBytes);
							}
							System.out.println("inPos[0] == " + inPos[0] + " in == " + in.length() + " pOutSzData ==  " + pOutSzData[0]);
							if(  null != ( bytes = readBytesFromFile(in, inPos, blklen, pOutSzData[0] - blklen) ) ){
								outBytes = new byte[bytes.length];
								if( 0 != ( res = p.xcry_decrypt(fd, bytes, outBytes) ) ){ System.out.println("p.xcry_decrypt: " + p.xcry_error(res)); return; }
								if(pOutNdxDataStart[0] <= blklen) writeBytesToFile(out, outPos, outBytes.length, outBytes);
								else { //copyOfRange(byte[] original, int from, int to)
									outBytes = Arrays.copyOfRange(outBytes, pOutNdxDataStart[0] - blklen, outBytes.length );  
									writeBytesToFile(out, outPos, outBytes.length, outBytes); }
							} 
						} */
       } finally {
    	    if(null != p) p.xcry_close(fd);
       }
   }
		
   public static void main_1(String args[]) {
     XCrypt p = new XCrypt();
     int eAlgo = XCRY_EALGO_3FISH256;
     int keylen = p.xcry_cipher_get_algo_keylen( eAlgo );
     int[] pFd = new int[]{ -1 };
     String sTwk = "Мама мыла раму! ";
     byte[] pTwk = sTwk.getBytes();
     byte[] pTwkOut = new byte[pTwk.length];
     System.out.println(sTwk + " : sTwk.length == " + sTwk.length() + " : pTwk.length == " + pTwk.length );
     System.out.println("p.xcry_open: " + p.xcry_open(pFd, eAlgo) );
     System.out.println("pFd: " + pFd[0]);
     System.out.println("keylen: " + keylen);

     System.out.println("xcry_settwk: " + p.xcry_settwk(pFd[0], pTwk));
     System.out.println("xcry_gettwk: " + p.xcry_gettwk(pFd[0], pTwkOut));
     System.out.println("pTwkOut: " + new String(pTwkOut));
   }
   static {
     System.loadLibrary("XCrypt");
   }
}
