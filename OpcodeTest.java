class OpcodeTest {
    public static void main(String[] args) {
        if (!OpcodeTest.class.desiredAssertionStatus()) {
            System.err.println("Need to enable assertions (-ea)");
            System.exit(1);
        }
        Opcodes op = new Opcodes();
        assert op.op_aconst_null() == null;
        assert op.op_iconst_m1() == -1;
        assert op.op_iconst_0() == 0;
        assert op.op_iconst_1() == 1;
        assert op.op_iconst_2() == 2;
        assert op.op_iconst_3() == 3;
        assert op.op_iconst_4() == 4;
        assert op.op_iconst_5() == 5;
        assert op.op_lconst_0() == 0;
        assert op.op_lconst_1() == 1;
        assert op.op_fconst_0() == 0;
        assert op.op_fconst_1() == 1;
        assert op.op_fconst_2() == 2;
        assert op.op_dconst_0() == 0;
        assert op.op_dconst_1() == 1;
        assert op.op_bipush() == 9;
        assert op.op_sipush() == 0x80;
        assert op.op_ldc() == 0x10000;
        //void op_ldc_w() { }
        //void op_ldc2_w() { }
        assert op.op_iload() == 0;
        assert op.op_lload() == 0;
        assert op.op_fload() == 0;
        assert op.op_dload() == 0;
        assert op.op_aload() == null;
        //int op_iload_0() { int a, b, c, d = 0; return d; }
        assert op.op_iload_1() == 0;
        assert op.op_iload_2() == 0;
        assert op.op_iload_3() == 0;
        //long op_lload_0() { long a, b, c, d = 0; return d; }
        assert op.op_lload_1() == 0;
        assert op.op_lload_2() == 0;
        assert op.op_lload_3() == 0;
        //float op_fload_0() { float a, b, c, d = 0; return d; }
        assert op.op_fload_1() == 0;
        assert op.op_fload_2() == 0;
        assert op.op_fload_3() == 0;
        //double op_dload_0() { double a, b, c, d = 0; return d; }
        assert op.op_dload_1() == 0;
        assert op.op_dload_2() == 0;
        assert op.op_dload_3() == 0;
        //Object op_aload_0() { Object a, b, c, d = null; return d; }
        assert op.op_aload_1() == null;
        assert op.op_aload_2() == null;
        assert op.op_aload_3() == null;
        assert op.op_iaload() == 0;
        assert op.op_laload() == 0;
        assert op.op_faload() == 0;
        assert op.op_daload() == 0;
        assert op.op_aaload() == null;
        assert op.op_baload() == 0;
        assert op.op_caload() == 0;
        assert op.op_saload() == 0;
        assert op.op_istore() == 0;
        assert op.op_lstore() == 0;
        assert op.op_fstore() == 0;
        assert op.op_dstore() == 0;
        assert op.op_astore() == null;
        //void op_istore_0() { }
        assert op.op_istore_1() == 0;
        assert op.op_istore_2() == 0;
        assert op.op_istore_3() == 0;
        //void op_lstore_0() { }
        assert op.op_lstore_1() == 0;
        assert op.op_lstore_2() == 0;
        assert op.op_lstore_3() == 0;
        //void op_fstore_0() { }
        assert op.op_fstore_1() == 0;
        assert op.op_fstore_2() == 0;
        assert op.op_fstore_3() == 0;
        //void op_dstore_0() { }
        assert op.op_dstore_1() == 0;
        assert op.op_dstore_2() == 0;
        assert op.op_dstore_3() == 0;
        //void op_astore_0() { }
        assert op.op_astore_1() == null;
        assert op.op_astore_2() == null;
        assert op.op_astore_3() == null;
        assert op.op_iastore() == 0;
        assert op.op_lastore() == 0;
        assert op.op_fastore() == 0;
        assert op.op_dastore() == 0;
        assert op.op_aastore() == null;
        assert op.op_bastore() == 0;
        assert op.op_castore() == 0;
        assert op.op_sastore() == 0;
        op.op_pop();
        op.op_pop2();
        //int op_dup() { int a = 0; return a + a; }
        //void op_dup_x1() { }
        //void op_dup_x2() { }
        //void op_dup2() { }
        //void op_dup2_x1() { }
        //void op_dup2_x2() { }
        //void op_swap() { }
        assert op.op_iadd(1, 2) == 3;
        assert op.op_ladd(1, 2) == 3;
        assert op.op_fadd(1, 2) == 3;
        assert op.op_dadd(1, 2) == 3;
        assert op.op_isub(3, 2) == 1;
        assert op.op_lsub(3, 2) == 1;
        assert op.op_fsub(3, 2) == 1;
        assert op.op_dsub(3, 2) == 1;
        assert op.op_imul(2, 3) == 6;
        assert op.op_lmul(2, 3) == 6;
        assert op.op_fmul(2, 3) == 6;
        assert op.op_dmul(2, 3) == 6;
        assert op.op_idiv(6, 3) == 2;
        assert op.op_ldiv(6, 3) == 2;
        assert op.op_fdiv(6, 3) == 2;
        assert op.op_ddiv(6, 3) == 2;
        assert op.op_irem(5, 3) == 2;
        assert op.op_lrem(5, 3) == 2;
        assert op.op_frem(5, 3) == 2;
        assert op.op_drem(5, 3) == 2;
        assert op.op_ineg(2) == -2;
        assert op.op_lneg(2) == -2;
        assert op.op_fneg(2) == -2;
        assert op.op_dneg(2) == -2;
        assert op.op_ishl(1, 2) == 4;
        assert op.op_lshl(1, 2) == 4;
        assert op.op_ishr(4, 1) == 2;
        assert op.op_lshr(4, 1) == 2;
        assert op.op_iushr(4, 1) == 2;
        assert op.op_lushr(4, 1) == 2;
        assert op.op_iand(5, 3) == 1;
        assert op.op_land(5, 3) == 1;
        assert op.op_ior(3, 5) == 7;
        assert op.op_lor(3, 5) == 7;
        assert op.op_ixor(3, 5) == 6;
        assert op.op_lxor(3, 5) == 6;
        assert op.op_iinc(1) == 2;
        assert op.op_i2l(2) == 2;
        assert op.op_i2f(2) == 2;
        assert op.op_i2d(2) == 2;
        assert op.op_l2i(2) == 2;
        assert op.op_l2f(2) == 2;
        assert op.op_l2d(2) == 2;
        assert op.op_f2i(2) == 2;
        assert op.op_f2l(2) == 2;
        assert op.op_f2d(2) == 2;
        assert op.op_d2i(2) == 2;
        assert op.op_d2l(2) == 2;
        assert op.op_d2f(2) == 2;
        assert op.op_i2b(2) == 2;
        assert op.op_i2c(2) == 2;
        assert op.op_i2s(2) == 2;
        assert op.op_lcmp(1, 2);
        //void op_fcmpl() { }
        assert op.op_fcmpg(1, 2);
        //void op_dcmpl() { }
        assert op.op_dcmpg(1, 2);
        assert op.op_ifeq(1);
        assert op.op_ifne(0);
        assert op.op_iflt(1);
        assert op.op_ifge(-1);
        assert op.op_ifgt(-1);
        assert op.op_ifle(1);
        assert op.op_if_icmpeq(1, 2);
        assert op.op_if_icmpne(1, 1);
        assert op.op_if_icmplt(2, 1);
        assert op.op_if_icmpge(1, 2);
        assert op.op_if_icmpgt(1, 2);
        assert op.op_if_icmple(2, 1);
        assert op.op_if_acmpeq(new Object(), null);
        assert op.op_if_acmpne(null, null);
        assert op.op_goto(1, 1);
        //int op_jsr() { try { if (op_iconst_0() == 0) return 1; } finally { op_iconst_1(); } return 0; }
        //void op_ret() { }
        assert op.op_tableswitch(2) == 2;
        assert op.op_lookupswitch(10) == 10;
        assert op.op_ireturn() == 0;
        assert op.op_lreturn() == 0;
        assert op.op_freturn() == 0;
        assert op.op_dreturn() == 0;
        assert op.op_areturn() == null;
        op.op_return();
        assert op.op_getstatic() == 0;
        op.op_putstatic(1); assert op.op_getstatic() == 1;
        assert op.op_getfield() == 0;
        op.op_putfield(1); assert op.op_getfield() == 1;
        assert op.op_invokevirtual(1) == 1;
        assert op.op_invokespecial(1) == 1;
        assert op.op_invokestatic(1) == 1;
        op.op_invokeinterface();
        assert op.op_new() != null;
        assert op.op_newarray() != null;
        assert op.op_anewarray() != null;
        assert op.op_arraylength() == 10;
        try { op.op_athrow(); assert false; } catch (Throwable x) { }
        assert op.op_checkcast(op) == op;
        assert op.op_instanceof(op);
        op.op_monitorenter();
        op.op_monitorexit();
        //void op_wide() { }
        assert op.op_multianewarray() != null;
        assert op.op_ifnull(op);
        assert op.op_ifnonnull(null);
        //void op_goto_w() { }
        //void op_jsr_w() { }
        //void op_breakpoint() { }
        //void op_ret_w() { }
        System.out.println("OpcodeTest succeeded");
    }
}
