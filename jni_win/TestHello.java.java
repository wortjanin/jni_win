// --------------------------------------------------
/**
 * @author vincent leung
 * @date Aug 5, 2009
 */
package leung;
public class TestHello {
    // methed that from c/c++ library
    public native void sayHello();
    static
    {
 // print the class paths in which the invoked c/c++ library files lie.
     System.out.println( System.getProperty("java.library.path"));
        System.loadLibrary("Hello");
    }
    public static void main(String[] args)
    {
     TestHello h = new TestHello();
        h.sayHello();
    }
}