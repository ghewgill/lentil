class Opcodes implements Runnable {
    static int static_field;
    int field;
    static void static_method() { }
    void method() { }
    private void private_method() { }
    public void run() { }

    // void op_nop() { }
    Object op_aconst_null() { return null; }
    int op_iconst_m1() { return -1; }
    int op_iconst_0() { return 0; }
    int op_iconst_1() { return 1; }
    int op_iconst_2() { return 2; }
    int op_iconst_3() { return 3; }
    int op_iconst_4() { return 4; }
    int op_iconst_5() { return 5; }
    long op_lconst_0() { return 0; }
    long op_lconst_1() { return 1; }
    float op_fconst_0() { return 0; }
    float op_fconst_1() { return 1; }
    float op_fconst_2() { return 2; }
    double op_dconst_0() { return 0; }
    double op_dconst_1() { return 1; }
    int op_bipush() { return 9; }
    char op_sipush() { return 0x80; }
    int op_ldc() { return 0x10000; }
    //void op_ldc_w() { }
    //void op_ldc2_w() { }
    int op_iload() { int a, b, c, d, e = 0; return e; }
    long op_lload() { long a, b, c, d, e = 0; return e; }
    float op_fload() { float a, b, c, d, e = 0; return e; }
    double op_dload() { double a, b, c, d, e = 0; return e; }
    Object op_aload() { Object a, b, c, d, e = null; return e; }
    //int op_iload_0() { int a, b, c, d = 0; return d; }
    int op_iload_1() { int a = 0; return a; }
    int op_iload_2() { int a, b = 0; return b; }
    int op_iload_3() { int a, b, c = 0; return c; }
    //long op_lload_0() { long a, b, c, d = 0; return d; }
    long op_lload_1() { long a = 0; return a; }
    long op_lload_2() { int a; long b = 0; return b; }
    long op_lload_3() { long a, b = 0; return b; }
    //float op_fload_0() { float a, b, c, d = 0; return d; }
    float op_fload_1() { float a = 0; return a; }
    float op_fload_2() { float a, b = 0; return b; }
    float op_fload_3() { float a, b, c = 0; return c; }
    //double op_dload_0() { double a, b, c, d = 0; return d; }
    double op_dload_1() { double a = 0; return a; }
    double op_dload_2() { int a; double b = 0; return b; }
    double op_dload_3() { double a, b = 0; return b; }
    //Object op_aload_0() { Object a, b, c, d = null; return d; }
    Object op_aload_1() { Object a = null; return a; }
    Object op_aload_2() { Object a, b = null; return b; }
    Object op_aload_3() { Object a, b, c = null; return c; }
    int op_iaload() { int[] a = null; return a[0]; }
    long op_laload() { long[] a = null; return a[0]; }
    float op_faload() { float[] a = null; return a[0]; }
    double op_daload() { double[] a = null; return a[0]; }
    Object op_aaload() { Object[] a = null; return a[0]; }
    int op_baload() { byte[] a = null; return a[0]; }
    int op_caload() { char[] a = null; return a[0]; }
    int op_saload() { short[] a = null; return a[0]; }
    void op_istore() { int a, b, c, d = 0; }
    void op_lstore() { long a, b, c = 0; }
    void op_fstore() { float a, b, c, d = 0; }
    void op_dstore() { double a, b, c = 0; }
    void op_astore() { Object a, b, c, d = null; }
    //void op_istore_0() { }
    void op_istore_1() { int a = 0; }
    void op_istore_2() { int a, b = 0; }
    void op_istore_3() { int a, b, c = 0; }
    //void op_lstore_0() { }
    void op_lstore_1() { long a = 0; }
    void op_lstore_2() { int a; long b = 0; }
    void op_lstore_3() { long a, b = 0; }
    //void op_fstore_0() { }
    void op_fstore_1() { float a = 0; }
    void op_fstore_2() { float a, b = 0; }
    void op_fstore_3() { float a, b, c = 0; }
    //void op_dstore_0() { }
    void op_dstore_1() { double a = 0; }
    void op_dstore_2() { int a; double b = 0; }
    void op_dstore_3() { double a, b = 0; }
    //void op_astore_0() { }
    void op_astore_1() { Object a = null; }
    void op_astore_2() { Object a, b = null; }
    void op_astore_3() { Object a, b, c = null; }
    void op_iastore() { int[] a = null; a[0] = 0; }
    void op_lastore() { long[] a = null; a[0] = 0; }
    void op_fastore() { float[] a = null; a[0] = 0; }
    void op_dastore() { double[] a = null; a[0] = 0; }
    void op_aastore() { Object[] a = null; a[0] = null; }
    void op_bastore() { byte[] a = null; a[0] = 0; }
    void op_castore() { char[] a = null; a[0] = 0; }
    void op_sastore() { short[] a = null; a[0] = 0; }
    void op_pop() { op_iconst_0(); }
    void op_pop2() { op_lconst_0(); }
    //int op_dup() { int a = 0; return a + a; }
    //void op_dup_x1() { }
    //void op_dup_x2() { }
    //void op_dup2() { }
    //void op_dup2_x1() { }
    //void op_dup2_x2() { }
    //void op_swap() { }
    int op_iadd(int a, int b) { return a + b; }
    long op_ladd(long a, long b) { return a + b; }
    float op_fadd(float a, float b) { return a + b; }
    double op_dadd(double a, double b) { return a + b; }
    int op_isub(int a, int b) { return a - b; }
    long op_lsub(long a, long b) { return a - b; }
    float op_fsub(float a, float b) { return a - b; }
    double op_dsub(double a, double b) { return a - b; }
    int op_imul(int a, int b) { return a * b; }
    long op_lmul(long a, long b) { return a * b; }
    float op_fmul(float a, float b) { return a * b; }
    double op_dmul(double a, double b) { return a * b; }
    int op_idiv(int a, int b) { return a / b; }
    long op_ldiv(long a, long b) { return a / b; }
    float op_fdiv(float a, float b) { return a / b; }
    double op_ddiv(double a, double b) { return a / b; }
    int op_irem(int a, int b) { return a % b; }
    long op_lrem(long a, long b) { return a % b; }
    float op_frem(float a, float b) { return a % b; }
    double op_drem(double a, double b) { return a % b; }
    int op_ineg(int a) { return -a; }
    long op_lneg(long a) { return -a; }
    float op_fneg(float a) { return -a; }
    double op_dneg(double a) { return -a; }
    int op_ishl(int a, int b) { return a << b; }
    long op_lshl(long a, long b) { return a << b; }
    int op_ishr(int a, int b) { return a >> b; }
    long op_lshr(long a, long b) { return a >> b; }
    int op_iushr(int a, int b) { return a >>> b; }
    long op_lushr(long a, long b) { return a >>> b; }
    int op_iand(int a, int b) { return a & b; }
    long op_land(long a, long b) { return a & b; }
    int op_ior(int a, int b) { return a | b; }
    long op_lor(long a, long b) { return a | b; }
    int op_ixor(int a, int b) { return a ^ b; }
    long op_lxor(long a, long b) { return a ^ b; }
    int op_iinc(int a) { return a++; }
    long op_i2l(int a) { return a; }
    float op_i2f(int a) { return a; }
    double op_i2d(int a) { return a; }
    int op_l2i(long a) { return (int)a; }
    float op_l2f(long a) { return a; }
    double op_l2d(long a) { return a; }
    int op_f2i(float a) { return (int)a; }
    long op_f2l(float a) { return (long)a; }
    double op_f2d(float a) { return a; }
    int op_d2i(double a) { return (int)a; }
    long op_d2l(double a) { return (long)a; }
    float op_d2f(double a) { return (float)a; }
    byte op_i2b(int a) { return (byte)a; }
    char op_i2c(int a) { return (char)a; }
    short op_i2s(int a) { return (short)a; }
    boolean op_lcmp(long a, long b) { return a < b; }
    //void op_fcmpl() { }
    boolean op_fcmpg(float a, float b) { return a < b; }
    //void op_dcmpl() { }
    boolean op_dcmpg(double a, double b) { return a < b; }
    boolean op_ifeq(int a) { return a != 0; }
    boolean op_ifne(int a) { return a == 0; }
    boolean op_iflt(int a) { return a >= 0; }
    boolean op_ifge(int a) { return a < 0; }
    boolean op_ifgt(int a) { return a <= 0; }
    boolean op_ifle(int a) { return a > 0; }
    boolean op_if_icmpeq(int a, int b) { return a != b; }
    boolean op_if_icmpne(int a, int b) { return a == b; }
    boolean op_if_icmplt(int a, int b) { return a >= b; }
    boolean op_if_icmpge(int a, int b) { return a < b; }
    boolean op_if_icmpgt(int a, int b) { return a <= b; }
    boolean op_if_icmple(int a, int b) { return a > b; }
    boolean op_if_acmpeq(Object a, Object b) { return a != b; }
    boolean op_if_acmpne(Object a, Object b) { return a == b; }
    boolean op_goto(int a, int b) { return a == b; }
    //int op_jsr() { try { if (op_iconst_0() == 0) return 1; } finally { op_iconst_1(); } return 0; }
    //void op_ret() { }
    void op_tableswitch(int a) { switch (a) { case 1: case 2: case 3: } }
    void op_lookupswitch(int a) { switch (a) { case 1: case 10: case 100: } }
    int op_ireturn() { return 0; }
    long op_lreturn() { return 0; }
    float op_freturn() { return 0; }
    double op_dreturn() { return 0; }
    Object op_areturn() { return null; }
    void op_return() { }
    Object op_getstatic() { return static_field; }
    void op_putstatic() { static_field = 0; }
    int op_getfield() { return field; }
    void op_putfield() { field = 0; }
    void op_invokevirtual() { method(); }
    void op_invokespecial() { private_method(); }
    void op_invokestatic() { static_method(); }
    void op_invokeinterface() { ((Runnable)this).run(); }
    Object op_new() { return new Object(); }
    int[] op_newarray() { return new int[10]; }
    Object[] op_anewarray() { return new Object[10]; }
    int op_arraylength() { return new int[10].length; }
    void op_athrow() throws Throwable { throw new Throwable("a"); }
    Object op_checkcast(Object a) { return (Opcodes)a; }
    boolean op_instanceof(Object a) { return a instanceof Opcodes; }
    void op_monitorenter() { synchronized (this) { } }
    void op_monitorexit() { synchronized (this) { } }
    //void op_wide() { }
    Object op_multianewarray() { return new int[10][10]; }
    boolean op_ifnull(Object a) { return a != null; }
    boolean op_ifnonnull(Object a) { return a == null; }
    //void op_goto_w() { }
    //void op_jsr_w() { }
    //void op_breakpoint() { }
    //void op_ret_w() { }
}
