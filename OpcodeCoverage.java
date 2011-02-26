import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class OpcodeCoverage {
    public static void main(String[] args) {
        int exitcode = 0;
        try {
            Process p = Runtime.getRuntime().exec(new String[] {"javap", "-c", "Opcodes"});
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String opcode = null;
            List<String> body = new ArrayList<String>();
            boolean found = false;
            while (true) {
                String s = in.readLine();
                if (s == null) {
                    break;
                }
                if (s.length() == 0) {
                    if (!found && opcode != null) {
                        System.out.println("opcode missing: " + opcode);
                        for (String t : body) {
                            System.out.println(t);
                        }
                        exitcode = 1;
                        System.exit(exitcode);
                    }
                    opcode = null;
                } else if (s.charAt(0) != ' ') {
                    Matcher m = Pattern.compile("\\S+ op_(\\w+)\\(").matcher(s);
                    if (m.lookingAt()) {
                        opcode = m.group(1);
                        body.clear();
                        found = false;
                    }
                } else {
                    body.add(s);
                    Matcher m = Pattern.compile("\\s+\\d+:\\s+(\\w+)").matcher(s);
                    if (m.lookingAt()) {
                        if (m.group(1).equals(opcode)) {
                            found = true;
                        }
                    }
                }
            }
        } catch (IOException x) {
            System.err.println(x);
        }
        System.exit(exitcode);
    }
}
