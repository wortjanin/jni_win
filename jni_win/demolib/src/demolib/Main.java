package demolib;

import java.io.*;
public class Main {

	public void sayHello() throws IOException{
		File f = new File("fileName.txt");
		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
		String str = "Hello!!!";
		bw.write(str);
		bw.close();
	}
	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		File f = new File("fileName.txt");
		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
		String str = "Hi .. Thanks a lot...";
		bw.write(str);
		bw.close();
	}

}
