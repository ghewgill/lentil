import org.mozilla.javascript.*;
import java.io.*;
import java.util.List;
import java.util.ArrayList;

public class FileLoader extends ScriptableObject {

//    private static final long serialVersionUID = 2549960399774237828L;
    public FileLoader() {
    }

    public static Scriptable jsConstructor(Context cx, Object[] args,
                                           Function ctorObj,
                                           boolean inNewExpr)
        throws IOException
    {
        FileLoader result = new FileLoader();
        result.file = new java.io.File(Context.toString(args[0]));
        result.inp = new FileInputStream(Context.toString(args[0]));
        return result;
    }

    @Override
    public String getClassName() {
        return "FileLoader";
    }

    public Object jsFunction_readAll() throws IOException
    {
        byte[] r = new byte[(int) file.length()];
        inp.read(r);
        return r;
    }

    public void jsFunction_close() throws IOException {
        inp.close();
    }

    @Override
    protected void finalize() {
        try {
            jsFunction_close();
        }
        catch (IOException e) {
        }
    }

    private static FileLoader checkInstance(Scriptable obj) {
        if (obj == null || !(obj instanceof FileLoader)) {
            throw Context.reportRuntimeError("called on incompatible object");
        }
        return (FileLoader) obj;
    }

    /**
     * Some private data for this class.
     */
    private java.io.File file;  // may be null, meaning to use System.out or .in
    private InputStream inp;
}
