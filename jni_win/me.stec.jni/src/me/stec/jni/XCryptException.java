package me.stec.jni;

public class XCryptException extends Throwable {
	private static final long serialVersionUID = 1L;
	String mistake;
	public XCryptException()
	{
		super();             // call superclass constructor
		mistake = "unknown";
	}
	  
	public XCryptException(String err)
	{
		super(err);     // call super class constructor
		mistake = err;  // save message
	}
	  
	public String getError()
	{
		return mistake;
	}
}
