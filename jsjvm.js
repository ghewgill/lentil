var CONSTANT_Utf8 = 1;
var CONSTANT_Integer = 3;
var CONSTANT_Float = 4;
var CONSTANT_Long = 5;
var CONSTANT_Double = 6;
var CONSTANT_Class = 7;
var CONSTANT_String = 8;
var CONSTANT_Fieldref = 9;
var CONSTANT_Methodref = 10;
var CONSTANT_InterfaceMethodref = 11;
var CONSTANT_NameAndType = 12;

var ACC_PUBLIC    = 0x0001;
var ACC_PRIVATE   = 0x0002;
var ACC_PROTECTED = 0x0004;
var ACC_STATIC    = 0x0008;
var ACC_FINAL     = 0x0010;
var ACC_SUPR      = 0x0020;
var ACC_SYNCHRONIZED = 0x0020;
var ACC_VOLATILE  = 0x0040;
var ACC_TRANSIENT = 0x0080;
var ACC_NATIVE    = 0x0100;
var ACC_INTERFACE = 0x0200;
var ACC_ABSTRACT  = 0x0400;
var ACC_STRICT    = 0x0800;

var op_nop              = 0;
var op_aconst_null      = 1;
var op_iconst_m1        = 2;
var op_iconst_0         = 3;
var op_iconst_1         = 4;
var op_iconst_2         = 5;
var op_iconst_3         = 6;
var op_iconst_4         = 7;
var op_iconst_5         = 8;
var op_lconst_0         = 9;
var op_lconst_1         = 10;
var op_fconst_0         = 11;
var op_fconst_1         = 12;
var op_fconst_2         = 13;
var op_dconst_0         = 14;
var op_dconst_1         = 15;
var op_bipush           = 16;
var op_sipush           = 17;
var op_ldc              = 18;
var op_ldc_w            = 19;
var op_ldc2_w           = 20;
var op_iload            = 21;
var op_lload            = 22;
var op_fload            = 23;
var op_dload            = 24;
var op_aload            = 25;
var op_iload_0          = 26;
var op_iload_1          = 27;
var op_iload_2          = 28;
var op_iload_3          = 29;
var op_lload_0          = 30;
var op_lload_1          = 31;
var op_lload_2          = 32;
var op_lload_3          = 33;
var op_fload_0          = 34;
var op_fload_1          = 35;
var op_fload_2          = 36;
var op_fload_3          = 37;
var op_dload_0          = 38;
var op_dload_1          = 39;
var op_dload_2          = 40;
var op_dload_3          = 41;
var op_aload_0          = 42;
var op_aload_1          = 43;
var op_aload_2          = 44;
var op_aload_3          = 45;
var op_iaload           = 46;
var op_laload           = 47;
var op_faload           = 48;
var op_daload           = 49;
var op_aaload           = 50;
var op_baload           = 51;
var op_caload           = 52;
var op_saload           = 53;
var op_istore           = 54;
var op_lstore           = 55;
var op_fstore           = 56;
var op_dstore           = 57;
var op_astore           = 58;
var op_istore_0         = 59;
var op_istore_1         = 60;
var op_istore_2         = 61;
var op_istore_3         = 62;
var op_lstore_0         = 63;
var op_lstore_1         = 64;
var op_lstore_2         = 65;
var op_lstore_3         = 66;
var op_fstore_0         = 67;
var op_fstore_1         = 68;
var op_fstore_2         = 69;
var op_fstore_3         = 70;
var op_dstore_0         = 71;
var op_dstore_1         = 72;
var op_dstore_2         = 73;
var op_dstore_3         = 74;
var op_astore_0         = 75;
var op_astore_1         = 76;
var op_astore_2         = 77;
var op_astore_3         = 78;
var op_iastore          = 79;
var op_lastore          = 80;
var op_fastore          = 81;
var op_dastore          = 82;
var op_aastore          = 83;
var op_bastore          = 84;
var op_castore          = 85;
var op_sastore          = 86;
var op_pop              = 87;
var op_pop2             = 88;
var op_dup              = 89;
var op_dup_x1           = 90;
var op_dup_x2           = 91;
var op_dup2             = 92;
var op_dup2_x1          = 93;
var op_dup2_x2          = 94;
var op_swap             = 95;
var op_iadd             = 96;
var op_ladd             = 97;
var op_fadd             = 98;
var op_dadd             = 99;
var op_isub             = 100;
var op_lsub             = 101;
var op_fsub             = 102;
var op_dsub             = 103;
var op_imul             = 104;
var op_lmul             = 105;
var op_fmul             = 106;
var op_dmul             = 107;
var op_idiv             = 108;
var op_ldiv             = 109;
var op_fdiv             = 110;
var op_ddiv             = 111;
var op_irem             = 112;
var op_lrem             = 113;
var op_frem             = 114;
var op_drem             = 115;
var op_ineg             = 116;
var op_lneg             = 117;
var op_fneg             = 118;
var op_dneg             = 119;
var op_ishl             = 120;
var op_lshl             = 121;
var op_ishr             = 122;
var op_lshr             = 123;
var op_iushr            = 124;
var op_lushr            = 125;
var op_iand             = 126;
var op_land             = 127;
var op_ior              = 128;
var op_lor              = 129;
var op_ixor             = 130;
var op_lxor             = 131;
var op_iinc             = 132;
var op_i2l              = 133;
var op_i2f              = 134;
var op_i2d              = 135;
var op_l2i              = 136;
var op_l2f              = 137;
var op_l2d              = 138;
var op_f2i              = 139;
var op_f2l              = 140;
var op_f2d              = 141;
var op_d2i              = 142;
var op_d2l              = 143;
var op_d2f              = 144;
var op_i2b              = 145;
var op_i2c              = 146;
var op_i2s              = 147;
var op_lcmp             = 148;
var op_fcmpl            = 149;
var op_fcmpg            = 150;
var op_dcmpl            = 151;
var op_dcmpg            = 152;
var op_ifeq             = 153;
var op_ifne             = 154;
var op_iflt             = 155;
var op_ifge             = 156;
var op_ifgt             = 157;
var op_ifle             = 158;
var op_if_icmpeq        = 159;
var op_if_icmpne        = 160;
var op_if_icmplt        = 161;
var op_if_icmpge        = 162;
var op_if_icmpgt        = 163;
var op_if_icmple        = 164;
var op_if_acmpeq        = 165;
var op_if_acmpne        = 166;
var op_goto             = 167;
var op_jsr              = 168;
var op_ret              = 169;
var op_tableswitch      = 170;
var op_lookupswitch     = 171;
var op_ireturn          = 172;
var op_lreturn          = 173;
var op_freturn          = 174;
var op_dreturn          = 175;
var op_areturn          = 176;
var op_return           = 177;
var op_getstatic        = 178;
var op_putstatic        = 179;
var op_getfield         = 180;
var op_putfield         = 181;
var op_invokevirtual    = 182;
var op_invokespecial    = 183;
var op_invokestatic     = 184;
var op_invokeinterface  = 185;
var op_new              = 187;
var op_newarray         = 188;
var op_anewarray        = 189;
var op_arraylength      = 190;
var op_athrow           = 191;
var op_checkcast        = 192;
var op_instanceof       = 193;
var op_monitorenter     = 194;
var op_monitorexit      = 195;
var op_wide             = 196;
var op_multianewarray   = 197;
var op_ifnull           = 198;
var op_ifnonnull        = 199;
var op_goto_w           = 200;
var op_jsr_w            = 201;
var op_breakpoint       = 202;
var op_ret_w            = 209;

Instruction = [
    "op_nop", "op_aconst_null", "op_iconst_m1", "op_iconst_0", "op_iconst_1",
    "op_iconst_2", "op_iconst_3", "op_iconst_4", "op_iconst_5", "op_lconst_0",
    "op_lconst_1", "op_fconst_0", "op_fconst_1", "op_fconst_2", "op_dconst_0",
    "op_dconst_1", "op_bipush", "op_sipush", "op_ldc", "op_ldc_w", "op_ldc2_w",
    "op_iload", "op_lload", "op_fload", "op_dload", "op_aload", "op_iload_0",
    "op_iload_1", "op_iload_2", "op_iload_3", "op_lload_0", "op_lload_1",
    "op_lload_2", "op_lload_3", "op_fload_0", "op_fload_1", "op_fload_2",
    "op_fload_3", "op_dload_0", "op_dload_1", "op_dload_2", "op_dload_3",
    "op_aload_0", "op_aload_1", "op_aload_2", "op_aload_3", "op_iaload",
    "op_laload", "op_faload", "op_daload", "op_aaload", "op_baload", "op_caload",
    "op_saload", "op_istore", "op_lstore", "op_fstore", "op_dstore", "op_astore",
    "op_istore_0", "op_istore_1", "op_istore_2", "op_istore_3", "op_lstore_0",
    "op_lstore_1", "op_lstore_2", "op_lstore_3", "op_fstore_0", "op_fstore_1",
    "op_fstore_2", "op_fstore_3", "op_dstore_0", "op_dstore_1", "op_dstore_2",
    "op_dstore_3", "op_astore_0", "op_astore_1", "op_astore_2", "op_astore_3",
    "op_iastore", "op_lastore", "op_fastore", "op_dastore", "op_aastore",
    "op_bastore", "op_castore", "op_sastore", "op_pop", "op_pop2", "op_dup",
    "op_dup_x1", "op_dup_x2", "op_dup2", "op_dup2_x1", "op_dup2_x2", "op_swap",
    "op_iadd", "op_ladd", "op_fadd", "op_dadd", "op_isub", "op_lsub", "op_fsub",
    "op_dsub", "op_imul", "op_lmul", "op_fmul", "op_dmul", "op_idiv", "op_ldiv",
    "op_fdiv", "op_ddiv", "op_irem", "op_lrem", "op_frem", "op_drem", "op_ineg",
    "op_lneg", "op_fneg", "op_dneg", "op_ishl", "op_lshl", "op_ishr", "op_lshr",
    "op_iushr", "op_lushr", "op_iand", "op_land", "op_ior", "op_lor", "op_ixor",
    "op_lxor", "op_iinc", "op_i2l", "op_i2f", "op_i2d", "op_l2i", "op_l2f",
    "op_l2d", "op_f2i", "op_f2l", "op_f2d", "op_d2i", "op_d2l", "op_d2f",
    "op_i2b", "op_i2c", "op_i2s", "op_lcmp", "op_fcmpl",
    "op_fcmpg", "op_dcmpl", "op_dcmpg", "op_ifeq", "op_ifne", "op_iflt", "op_ifge",
    "op_ifgt", "op_ifle", "op_if_icmpeq", "op_if_icmpne", "op_if_icmplt",
    "op_if_icmpge", "op_if_icmpgt", "op_if_icmple", "op_if_acmpeq", "op_if_acmpne",
    "op_goto", "op_jsr", "op_ret", "op_tableswitch", "op_lookupswitch",
    "op_ireturn", "op_lreturn", "op_freturn", "op_dreturn", "op_areturn",
    "op_return", "op_getstatic", "op_putstatic", "op_getfield", "op_putfield",
    "op_invokevirtual", "op_invokespecial", "op_invokestatic",
    "op_invokeinterface", "op_186", "op_new", "op_newarray", "op_anewarray",
    "op_arraylength", "op_athrow", "op_checkcast", "op_instanceof",
    "op_monitorenter", "op_monitorexit", "op_wide", "op_multianewarray",
    "op_ifnull", "op_ifnonnull", "op_goto_w", "op_jsr_w", "op_breakpoint",
    "op_203", "op_204", "op_205", "op_206", "op_207", "op_ret_w"
];

function ClassError(msg) {
    this.name = "ClassError";
    this.message = msg;
}

function DataInput(bytes) {
    this.data = bytes;
    this.index = 0;

    this.readBytes = function(n) {
        var r = [];
        for (var i = 0; i < n; i++) {
            r[i] = this.readUnsignedByte();
        }
        return r;
    }

    this.readInt = function() {
        return this.readN(4);
    };

    this.readUnsignedByte = function() {
        return this.readN(1);
    }

    this.readUnsignedInt = function() {
        return this.readN(4);
    };

    this.readUnsignedShort = function() {
        return this.readN(2);
    }

    this.readN = function(n) {
        var r = 0;
        while (n > 0) {
            r = (r << 8) | (this.data[this.index] & 0xff);
            this.index++;
            n--;
        }
        return r;
    }

    this.remaining = function() {
        return this.data.length - this.index;
    }
}

function disassemble(code) {
    for (var i = 0; i < code.length; i++) {
        var ins = Instruction[code[i][0]];
        for (var j = 1; j < code[i].length; j++) {
            ins += j === 1 ? "  " : ", ";
            ins += code[i][j];
        }
        print("      " + ins);
    }
}

function ConstantClass(cls, din) {
    this.cls = cls;
    this.name_index = din.readUnsignedShort();

    this.resolve = function() {
        this.name = this.cls.constant_pool[this.name_index].toString();
    }

    this.toString = function() {
        return "<class " + this.name + ">";
    }
}

function ConstantFieldref(cls, din) {
    this.cls = cls;
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.resolve = function() {
        this.classref = this.cls.constant_pool[this.class_index];
        this.name_and_type = this.cls.constant_pool[this.name_and_type_index];
    }

    this.toString = function() {
        return "<fieldref " + this.classref + " " + this.name_and_type + ">";
    }
}

function ConstantMethodref(cls, din) {
    this.cls = cls;
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.resolve = function() {
        this.classref = this.cls.constant_pool[this.class_index];
        this.name_and_type = this.cls.constant_pool[this.name_and_type_index];
    }

    this.toString = function() {
        return "<methodref " + this.classref + " " + this.name_and_type + ">";
    }
}

function ConstantNameAndType(cls, din) {
    this.cls = cls;
    this.name_index = din.readUnsignedShort();
    this.descriptor_index = din.readUnsignedShort();

    this.resolve = function() {
        this.name = this.cls.constant_pool[this.name_index].toString();
        this.descriptor = this.cls.constant_pool[this.descriptor_index].toString();
    }

    this.toString = function() {
        return "<nameandtype " + this.name + " " + this.descriptor + ">";
    }
}

function ConstantString(cls, din) {
    this.cls = cls;
    this.string_index = din.readUnsignedShort();

    this.resolve = function() {
        this.string = this.cls.classloader.getClass("java/lang/String").newInstance(this.cls.constant_pool[this.string_index].toString());
    }

    this.toString = function() {
        return "<string " + this.string + ">";
    }

    this.value = function() {
        return this.string;
    }
}

function ConstantUtf8(cls, din) {
    this.length = din.readUnsignedShort();
    this.bytes = din.readBytes(this.length);

    this.resolve = function() {}

    this.toString = function() {
        var r = "";
        for (var i = 0; i < this.length; i++) {
            r += String.fromCharCode(this.bytes[i]);
        }
        return r;
    }
}

function decodeBytecode(code) {
    var r = [];
    for (var i = 0; i < code.length; i++) {
        var ins;
        switch (code[i]) {
            //case op_nop:
            //case op_aconst_null:
            //case op_iconst_m1:
            //case op_iconst_0:
            //case op_iconst_1:
            //case op_iconst_2:
            //case op_iconst_3:
            //case op_iconst_4:
            //case op_iconst_5:
            //case op_lconst_0:
            //case op_lconst_1:
            //case op_fconst_0:
            //case op_fconst_1:
            //case op_fconst_2:
            //case op_dconst_0:
            //case op_dconst_1:
            //case op_bipush:
            //case op_sipush:
            case op_ldc:
                ins = [op_ldc, code[i+1]];
                i += 1;
                break;
            //case op_ldc_w:
            //case op_ldc2_w:
            //case op_iload:
            //case op_lload:
            //case op_fload:
            //case op_dload:
            //case op_aload:
            //case op_iload_0:
            //case op_iload_1:
            //case op_iload_2:
            //case op_iload_3:
            //case op_lload_0:
            //case op_lload_1:
            //case op_lload_2:
            //case op_lload_3:
            //case op_fload_0:
            //case op_fload_1:
            //case op_fload_2:
            //case op_fload_3:
            //case op_dload_0:
            //case op_dload_1:
            //case op_dload_2:
            //case op_dload_3:
            case op_aload_0:
                ins = [op_aload, 0];
                break;
            //case op_aload_1:
            //case op_aload_2:
            //case op_aload_3:
            //case op_iaload:
            //case op_laload:
            //case op_faload:
            //case op_daload:
            case op_aaload:
                ins = [op_aaload];
                break;
            //case op_baload:
            //case op_caload:
            //case op_saload:
            //case op_istore:
            //case op_lstore:
            //case op_fstore:
            //case op_dstore:
            //case op_astore:
            //case op_istore_0:
            //case op_istore_1:
            //case op_istore_2:
            //case op_istore_3:
            //case op_lstore_0:
            //case op_lstore_1:
            //case op_lstore_2:
            //case op_lstore_3:
            //case op_fstore_0:
            //case op_fstore_1:
            //case op_fstore_2:
            //case op_fstore_3:
            //case op_dstore_0:
            //case op_dstore_1:
            //case op_dstore_2:
            //case op_dstore_3:
            //case op_astore_0:
            //case op_astore_1:
            //case op_astore_2:
            //case op_astore_3:
            //case op_iastore:
            //case op_lastore:
            //case op_fastore:
            //case op_dastore:
            //case op_aastore:
            //case op_bastore:
            //case op_castore:
            //case op_sastore:
            //case op_pop:
            //case op_pop2:
            //case op_dup:
            //case op_dup_x1:
            //case op_dup_x2:
            //case op_dup2:
            //case op_dup2_x1:
            //case op_dup2_x2:
            //case op_swap:
            //case op_iadd:
            //case op_ladd:
            //case op_fadd:
            //case op_dadd:
            //case op_isub:
            //case op_lsub:
            //case op_fsub:
            //case op_dsub:
            //case op_imul:
            //case op_lmul:
            //case op_fmul:
            //case op_dmul:
            //case op_idiv:
            //case op_ldiv:
            //case op_fdiv:
            //case op_ddiv:
            //case op_irem:
            //case op_lrem:
            //case op_frem:
            //case op_drem:
            //case op_ineg:
            //case op_lneg:
            //case op_fneg:
            //case op_dneg:
            //case op_ishl:
            //case op_lshl:
            //case op_ishr:
            //case op_lshr:
            //case op_iushr:
            //case op_lushr:
            //case op_iand:
            //case op_land:
            //case op_ior:
            //case op_lor:
            //case op_ixor:
            //case op_lxor:
            //case op_iinc:
            //case op_i2l:
            //case op_i2f:
            //case op_i2d:
            //case op_l2i:
            //case op_l2f:
            //case op_l2d:
            //case op_f2i:
            //case op_f2l:
            //case op_f2d:
            //case op_d2i:
            //case op_d2l:
            //case op_d2f:
            //case op_i2b:
            //case op_i2c:
            //case op_i2s:
            //case op_lcmp:
            //case op_fcmpl:
            //case op_fcmpg:
            //case op_dcmpl:
            //case op_dcmpg:
            //case op_ifeq:
            //case op_ifne:
            //case op_iflt:
            //case op_ifge:
            //case op_ifgt:
            //case op_ifle:
            //case op_if_icmpeq:
            //case op_if_icmpne:
            //case op_if_icmplt:
            //case op_if_icmpge:
            //case op_if_icmpgt:
            //case op_if_icmple:
            //case op_if_acmpeq:
            //case op_if_acmpne:
            //case op_goto:
            //case op_jsr:
            //case op_ret:
            //case op_tableswitch:
            //case op_lookupswitch:
            //case op_ireturn:
            //case op_lreturn:
            //case op_freturn:
            //case op_dreturn:
            //case op_areturn:
            case op_return:
                ins = [op_return];
                break;
            case op_getstatic:
                ins = [op_getstatic, (code[i+1] << 8) | code[i+2]];
                i += 2;
                break;
            //case op_putstatic:
            //case op_getfield:
            //case op_putfield:
            case op_invokevirtual:
                ins = [op_invokevirtual, (code[i+1] << 8) | code[i+2]];
                i += 2;
                break;
            case op_invokespecial:
                ins = [op_invokespecial, (code[i+1] << 8) | code[i+2]];
                i += 2;
                break;
            //case op_invokestatic:
            //case op_invokeinterface:
            //case op_new:
            //case op_newarray:
            //case op_anewarray:
            //case op_arraylength:
            //case op_athrow:
            //case op_checkcast:
            //case op_instanceof:
            //case op_monitorenter:
            //case op_monitorexit:
            //case op_wide:
            //case op_multianewarray:
            //case op_ifnull:
            //case op_ifnonnull:
            //case op_goto_w:
            //case op_jsr_w:
            //case op_breakpoint:
            //case op_ret_w:
            default:
                throw ("Unknown opcode: " + code[i]);
        }
        r[r.length] = ins;
    }
    return r;
}

var AttributeDecoder = {
    "Code": function(cls, din) {
        this.cls = cls;
        this.max_stack = din.readUnsignedShort();
        this.max_locals = din.readUnsignedShort();
        this.code_length = din.readUnsignedInt();
        this.code = decodeBytecode(din.readBytes(this.code_length));
        this.exception_table_length = din.readUnsignedShort();
        this.exception_table = [];
        for (var i = 0; i < this.exception_table_length; i++) {
            this.exception_table[i] = new ExceptionTableEntry(din);
        }
        this.attributes_count = din.readUnsignedShort();
        this.attributes = [];
        for (var i = 0; i < this.attributes_count; i++) {
            this.attributes[i] = new Attribute(cls, din);
        }

        this.dump = function() {
            print("    max_stack:", this.max_stack);
            print("    max_locals:", this.max_locals);
            print("    code_length:", this.code_length);
            disassemble(this.code);
            print("    exception_table_length:", this.exception_table_length);
            for (var i = 0; i < this.exception_table_length; i++) {
                this.exception_table_length[i].dump();
            }
            print("    attributes_count:", this.attributes_count);
            for (var i = 0; i < this.attributes_count; i++) {
                this.attributes[i].dump();
            }
        }
    },
    //"ConstantValue": function(cls, din) {
    //    print("here");
    //},
    "SourceFile": function(cls, din) {
        this.cls = cls;
        this.sourcefile_index = din.readUnsignedShort();

        this.sourcefile = this.cls.constant_pool[this.sourcefile_index];

        this.dump = function() {
            print("    " + this.sourcefile);
        }
    }
}

function Attribute(cls, din) {
    this.cls = cls;
    this.attribute_name_index = din.readUnsignedShort();
    this.attribute_length = din.readUnsignedInt();
    this.info = din.readBytes(this.attribute_length);

    var name = cls.constant_pool[this.attribute_name_index].toString();
    if (name in AttributeDecoder) {
        this.attr = new AttributeDecoder[name](cls, new DataInput(this.info));
    } else {
        //print("Ignored attribute:", name);
    }

    this.attribute_name = cls.constant_pool[this.attribute_name_index].toString();

    this.dump = function() {
        print("    attribute_name:", this.attribute_name);
        print("    attribute_length:", this.attribute_length);
        if (this.attr) {
            this.attr.dump();
        }
    }
}

function FieldInfo(cls, din) {
    this.cls = cls;
    this.access_flags = din.readUnsignedShort();
    this.name_index = din.readUnsignedShort();
    this.descriptor_index = din.readUnsignedShort();
    this.attributes_count = din.readUnsignedShort();
    this.attributes = [];
    for (var i = 0; i < this.attributes_count; i++) {
        this.attributes[i] = new Attribute(cls, din);
    }

    this.dump = function() {
        print("  access_flags:", this.access_flags);
        print("  name_index:", this.name_index);
        print("  descriptor_index:", this.descriptor_index);
        print("  attributes_count:", this.attributes_count);
        for (var i = 0; i < this.attributes_count; i++) {
            this.attributes[i].dump();
        }
    }
}

function MethodInfo(cls, din) {
    this.cls = cls;
    this.access_flags = din.readUnsignedShort();
    this.name_index = din.readUnsignedShort();
    this.descriptor_index = din.readUnsignedShort();
    this.attributes_count = din.readUnsignedShort();
    this.attributes = [];
    this.attribute_by_name = [];
    for (var i = 0; i < this.attributes_count; i++) {
        var a = new Attribute(cls, din);
        this.attributes[i] = a;
        this.attribute_by_name[a.attribute_name] = a;
    }

    this.name = cls.constant_pool[this.name_index].toString();
    this.descriptor = cls.constant_pool[this.descriptor_index].toString();
    this.full_name = this.name + this.descriptor;

    this.dump = function() {
        print("  access_flags:", this.access_flags);
        print("  name:", this.name);
        print("  descriptor:", this.descriptor);
        print("  attributes_count:", this.attributes_count);
        for (var i = 0; i < this.attributes_count; i++) {
            this.attributes[i].dump();
        }
    }
}

function getNargs(descriptor) {
    var nargs = 0;
    var i = 1;
    while (descriptor.charAt(i) !== ")") {
        if (descriptor.charAt(i) === "[") {
            i++;
            continue;
        }
        if (descriptor.charAt(i) === "L") {
            i = descriptor.indexOf(";", i) + 1;
            nargs++;
            continue;
        }
        i += 1;
        nargs++;
    }
    return nargs;
}

Opcode = [
    
    // op_nop
    function(cls, env, ins, pc) {
    },
    
    // op_aconst_null
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_m1
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_0
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_1
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_2
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_3
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_4
    function(cls, env, ins, pc) {
    },
    
    // op_iconst_5
    function(cls, env, ins, pc) {
    },
    
    // op_lconst_0
    function(cls, env, ins, pc) {
    },
    
    // op_lconst_1
    function(cls, env, ins, pc) {
    },
    
    // op_fconst_0
    function(cls, env, ins, pc) {
    },
    
    // op_fconst_1
    function(cls, env, ins, pc) {
    },
    
    // op_fconst_2
    function(cls, env, ins, pc) {
    },
    
    // op_dconst_0
    function(cls, env, ins, pc) {
    },
    
    // op_dconst_1
    function(cls, env, ins, pc) {
    },
    
    // op_bipush
    function(cls, env, ins, pc) {
    },
    
    // op_sipush
    function(cls, env, ins, pc) {
    },
    
    // op_ldc
    function(cls, env, ins, pc) {
        env.push(cls.constant_pool[ins[1]].value());
        return pc + 1;
    },
    
    // op_ldc_w
    function(cls, env, ins, pc) {
    },
    
    // op_ldc2_w
    function(cls, env, ins, pc) {
    },
    
    // op_iload
    function(cls, env, ins, pc) {
    },
    
    // op_lload
    function(cls, env, ins, pc) {
    },
    
    // op_fload
    function(cls, env, ins, pc) {
    },
    
    // op_dload
    function(cls, env, ins, pc) {
    },
    
    // op_aload
    function(cls, env, ins, pc) {
    },
    
    // op_iload_0
    function(cls, env, ins, pc) {
    },
    
    // op_iload_1
    function(cls, env, ins, pc) {
    },
    
    // op_iload_2
    function(cls, env, ins, pc) {
    },
    
    // op_iload_3
    function(cls, env, ins, pc) {
    },
    
    // op_lload_0
    function(cls, env, ins, pc) {
    },
    
    // op_lload_1
    function(cls, env, ins, pc) {
    },
    
    // op_lload_2
    function(cls, env, ins, pc) {
    },
    
    // op_lload_3
    function(cls, env, ins, pc) {
    },
    
    // op_fload_0
    function(cls, env, ins, pc) {
    },
    
    // op_fload_1
    function(cls, env, ins, pc) {
    },
    
    // op_fload_2
    function(cls, env, ins, pc) {
    },
    
    // op_fload_3
    function(cls, env, ins, pc) {
    },
    
    // op_dload_0
    function(cls, env, ins, pc) {
    },
    
    // op_dload_1
    function(cls, env, ins, pc) {
    },
    
    // op_dload_2
    function(cls, env, ins, pc) {
    },
    
    // op_dload_3
    function(cls, env, ins, pc) {
    },
    
    // op_aload_0
    function(cls, env, ins, pc) {
    },
    
    // op_aload_1
    function(cls, env, ins, pc) {
    },
    
    // op_aload_2
    function(cls, env, ins, pc) {
    },
    
    // op_aload_3
    function(cls, env, ins, pc) {
    },
    
    // op_iaload
    function(cls, env, ins, pc) {
    },
    
    // op_laload
    function(cls, env, ins, pc) {
    },
    
    // op_faload
    function(cls, env, ins, pc) {
    },
    
    // op_daload
    function(cls, env, ins, pc) {
    },
    
    // op_aaload
    function(cls, env, ins, pc) {
    },
    
    // op_baload
    function(cls, env, ins, pc) {
    },
    
    // op_caload
    function(cls, env, ins, pc) {
    },
    
    // op_saload
    function(cls, env, ins, pc) {
    },
    
    // op_istore
    function(cls, env, ins, pc) {
    },
    
    // op_lstore
    function(cls, env, ins, pc) {
    },
    
    // op_fstore
    function(cls, env, ins, pc) {
    },
    
    // op_dstore
    function(cls, env, ins, pc) {
    },
    
    // op_astore
    function(cls, env, ins, pc) {
    },
    
    // op_istore_0
    function(cls, env, ins, pc) {
    },
    
    // op_istore_1
    function(cls, env, ins, pc) {
    },
    
    // op_istore_2
    function(cls, env, ins, pc) {
    },
    
    // op_istore_3
    function(cls, env, ins, pc) {
    },
    
    // op_lstore_0
    function(cls, env, ins, pc) {
    },
    
    // op_lstore_1
    function(cls, env, ins, pc) {
    },
    
    // op_lstore_2
    function(cls, env, ins, pc) {
    },
    
    // op_lstore_3
    function(cls, env, ins, pc) {
    },
    
    // op_fstore_0
    function(cls, env, ins, pc) {
    },
    
    // op_fstore_1
    function(cls, env, ins, pc) {
    },
    
    // op_fstore_2
    function(cls, env, ins, pc) {
    },
    
    // op_fstore_3
    function(cls, env, ins, pc) {
    },
    
    // op_dstore_0
    function(cls, env, ins, pc) {
    },
    
    // op_dstore_1
    function(cls, env, ins, pc) {
    },
    
    // op_dstore_2
    function(cls, env, ins, pc) {
    },
    
    // op_dstore_3
    function(cls, env, ins, pc) {
    },
    
    // op_astore_0
    function(cls, env, ins, pc) {
    },
    
    // op_astore_1
    function(cls, env, ins, pc) {
    },
    
    // op_astore_2
    function(cls, env, ins, pc) {
    },
    
    // op_astore_3
    function(cls, env, ins, pc) {
    },
    
    // op_iastore
    function(cls, env, ins, pc) {
    },
    
    // op_lastore
    function(cls, env, ins, pc) {
    },
    
    // op_fastore
    function(cls, env, ins, pc) {
    },
    
    // op_dastore
    function(cls, env, ins, pc) {
    },
    
    // op_aastore
    function(cls, env, ins, pc) {
    },
    
    // op_bastore
    function(cls, env, ins, pc) {
    },
    
    // op_castore
    function(cls, env, ins, pc) {
    },
    
    // op_sastore
    function(cls, env, ins, pc) {
    },
    
    // op_pop
    function(cls, env, ins, pc) {
    },
    
    // op_pop2
    function(cls, env, ins, pc) {
    },
    
    // op_dup
    function(cls, env, ins, pc) {
    },
    
    // op_dup_x1
    function(cls, env, ins, pc) {
    },
    
    // op_dup_x2
    function(cls, env, ins, pc) {
    },
    
    // op_dup2
    function(cls, env, ins, pc) {
    },
    
    // op_dup2_x1
    function(cls, env, ins, pc) {
    },
    
    // op_dup2_x2
    function(cls, env, ins, pc) {
    },
    
    // op_swap
    function(cls, env, ins, pc) {
    },
    
    // op_iadd
    function(cls, env, ins, pc) {
    },
    
    // op_ladd
    function(cls, env, ins, pc) {
    },
    
    // op_fadd
    function(cls, env, ins, pc) {
    },
    
    // op_dadd
    function(cls, env, ins, pc) {
    },
    
    // op_isub
    function(cls, env, ins, pc) {
    },
    
    // op_lsub
    function(cls, env, ins, pc) {
    },
    
    // op_fsub
    function(cls, env, ins, pc) {
    },
    
    // op_dsub
    function(cls, env, ins, pc) {
    },
    
    // op_imul
    function(cls, env, ins, pc) {
    },
    
    // op_lmul
    function(cls, env, ins, pc) {
    },
    
    // op_fmul
    function(cls, env, ins, pc) {
    },
    
    // op_dmul
    function(cls, env, ins, pc) {
    },
    
    // op_idiv
    function(cls, env, ins, pc) {
    },
    
    // op_ldiv
    function(cls, env, ins, pc) {
    },
    
    // op_fdiv
    function(cls, env, ins, pc) {
    },
    
    // op_ddiv
    function(cls, env, ins, pc) {
    },
    
    // op_irem
    function(cls, env, ins, pc) {
    },
    
    // op_lrem
    function(cls, env, ins, pc) {
    },
    
    // op_frem
    function(cls, env, ins, pc) {
    },
    
    // op_drem
    function(cls, env, ins, pc) {
    },
    
    // op_ineg
    function(cls, env, ins, pc) {
    },
    
    // op_lneg
    function(cls, env, ins, pc) {
    },
    
    // op_fneg
    function(cls, env, ins, pc) {
    },
    
    // op_dneg
    function(cls, env, ins, pc) {
    },
    
    // op_ishl
    function(cls, env, ins, pc) {
    },
    
    // op_lshl
    function(cls, env, ins, pc) {
    },
    
    // op_ishr
    function(cls, env, ins, pc) {
    },
    
    // op_lshr
    function(cls, env, ins, pc) {
    },
    
    // op_iushr
    function(cls, env, ins, pc) {
    },
    
    // op_lushr
    function(cls, env, ins, pc) {
    },
    
    // op_iand
    function(cls, env, ins, pc) {
    },
    
    // op_land
    function(cls, env, ins, pc) {
    },
    
    // op_ior
    function(cls, env, ins, pc) {
    },
    
    // op_lor
    function(cls, env, ins, pc) {
    },
    
    // op_ixor
    function(cls, env, ins, pc) {
    },
    
    // op_lxor
    function(cls, env, ins, pc) {
    },
    
    // op_iinc
    function(cls, env, ins, pc) {
    },
    
    // op_i2l
    function(cls, env, ins, pc) {
    },
    
    // op_i2f
    function(cls, env, ins, pc) {
    },
    
    // op_i2d
    function(cls, env, ins, pc) {
    },
    
    // op_l2i
    function(cls, env, ins, pc) {
    },
    
    // op_l2f
    function(cls, env, ins, pc) {
    },
    
    // op_l2d
    function(cls, env, ins, pc) {
    },
    
    // op_f2i
    function(cls, env, ins, pc) {
    },
    
    // op_f2l
    function(cls, env, ins, pc) {
    },
    
    // op_f2d
    function(cls, env, ins, pc) {
    },
    
    // op_d2i
    function(cls, env, ins, pc) {
    },
    
    // op_d2l
    function(cls, env, ins, pc) {
    },
    
    // op_d2f
    function(cls, env, ins, pc) {
    },
    
    // op_i2b
    function(cls, env, ins, pc) {
    },
    
    // op_i2c
    function(cls, env, ins, pc) {
    },
    
    // op_i2s
    function(cls, env, ins, pc) {
    },
    
    // op_lcmp
    function(cls, env, ins, pc) {
    },
    
    // op_fcmpl
    function(cls, env, ins, pc) {
    },
    
    // op_fcmpg
    function(cls, env, ins, pc) {
    },
    
    // op_dcmpl
    function(cls, env, ins, pc) {
    },
    
    // op_dcmpg
    function(cls, env, ins, pc) {
    },
    
    // op_ifeq
    function(cls, env, ins, pc) {
    },
    
    // op_ifne
    function(cls, env, ins, pc) {
    },
    
    // op_iflt
    function(cls, env, ins, pc) {
    },
    
    // op_ifge
    function(cls, env, ins, pc) {
    },
    
    // op_ifgt
    function(cls, env, ins, pc) {
    },
    
    // op_ifle
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmpeq
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmpne
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmplt
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmpge
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmpgt
    function(cls, env, ins, pc) {
    },
    
    // op_if_icmple
    function(cls, env, ins, pc) {
    },
    
    // op_if_acmpeq
    function(cls, env, ins, pc) {
    },
    
    // op_if_acmpne
    function(cls, env, ins, pc) {
    },
    
    // op_goto
    function(cls, env, ins, pc) {
    },
    
    // op_jsr
    function(cls, env, ins, pc) {
    },
    
    // op_ret
    function(cls, env, ins, pc) {
    },
    
    // op_tableswitch
    function(cls, env, ins, pc) {
    },
    
    // op_lookupswitch
    function(cls, env, ins, pc) {
    },
    
    // op_ireturn
    function(cls, env, ins, pc) {
    },
    
    // op_lreturn
    function(cls, env, ins, pc) {
    },
    
    // op_freturn
    function(cls, env, ins, pc) {
    },
    
    // op_dreturn
    function(cls, env, ins, pc) {
    },
    
    // op_areturn
    function(cls, env, ins, pc) {
    },
    
    // op_return
    function(cls, env, ins, pc) {
        return -1;
    },
    
    // op_getstatic
    function(cls, env, ins, pc) {
        var fr = cls.constant_pool[ins[1]];
        env.push(getField(cls.classloader.getClass(fr.classref.name), fr.name_and_type.name));
        return pc + 1;
    },
    
    // op_putstatic
    function(cls, env, ins, pc) {
    },
    
    // op_getfield
    function(cls, env, ins, pc) {
    },
    
    // op_putfield
    function(cls, env, ins, pc) {
    },
    
    // op_invokevirtual
    function(cls, env, ins, pc) {
        var mr = cls.constant_pool[ins[1]];
        var nargs = getNargs(mr.name_and_type.descriptor);
        var args = [];
        while (nargs--) {
            args[nargs] = env.pop();
        }
        var obj = env.pop();
        cls.exec(env, mr.name_and_type.name + mr.name_and_type.descriptor, obj, args);
        return pc + 1;
    },
    
    // op_invokespecial
    function(cls, env, ins, pc) {
    },
    
    // op_invokestatic
    function(cls, env, ins, pc) {
    },
    
    // op_invokeinterface
    function(cls, env, ins, pc) {
    },
    
    // op_new
    function(cls, env, ins, pc) {
    },
    
    // op_newarray
    function(cls, env, ins, pc) {
    },
    
    // op_anewarray
    function(cls, env, ins, pc) {
    },
    
    // op_arraylength
    function(cls, env, ins, pc) {
    },
    
    // op_athrow
    function(cls, env, ins, pc) {
    },
    
    // op_checkcast
    function(cls, env, ins, pc) {
    },
    
    // op_instanceof
    function(cls, env, ins) {
    },
    
    // op_monitorenter
    function(cls, env, ins, pc) {
    },
    
    // op_monitorexit
    function(cls, env, ins, pc) {
    },
    
    // op_wide
    function(cls, env, ins, pc) {
    },
    
    // op_multianewarray
    function(cls, env, ins, pc) {
    },
    
    // op_ifnull
    function(cls, env, ins, pc) {
    },
    
    // op_ifnonnull
    function(cls, env, ins, pc) {
    },
    
    // op_goto_w
    function(cls, env, ins, pc) {
    },
    
    // op_jsr_w
    function(cls, env, ins, pc) {
    },
    
    // op_breakpoint
    function(cls, env, ins, pc) {
    },
    
    // op_ret_w
    function(cls, env, ins, pc) {
    }
];

function Class(classloader, bytes) {
    this.classloader = classloader;
    var din = new DataInput(bytes);
    this.magic = din.readInt();
    this.minor_version = din.readUnsignedShort();
    this.major_version = din.readUnsignedShort();
    this.constant_pool_count = din.readUnsignedShort();
    this.constant_pool = [];
    for (var i = 1; i < this.constant_pool_count; i++) {
        var tag = din.readUnsignedByte();
        var cp;
        switch (tag) {
            case CONSTANT_Utf8:                 cp = new ConstantUtf8(this, din);     break;
            case CONSTANT_Integer:              cp = new ConstantInteger(this, din);  break;
            case CONSTANT_Float:                cp = new ConstantFloat(this, din);    break;
            case CONSTANT_Long:                 cp = new ConstantLong(this, din);     break;
            case CONSTANT_Double:               cp = new ConstantDouble(this, din);   break;
            case CONSTANT_Class:                cp = new ConstantClass(this, din);    break;
            case CONSTANT_String:               cp = new ConstantString(this, din);   break;
            case CONSTANT_Fieldref:             cp = new ConstantFieldref(this, din); break;
            case CONSTANT_Methodref:            cp = new ConstantMethodref(this, din); break;
            case CONSTANT_InterfaceMethodref:   cp = new ConstantInterfaceMethodref(this, din); break;
            case CONSTANT_NameAndType:          cp = new ConstantNameAndType(this, din); break;
            default:
                throw ("Unknown constant pool tag: " + tag);
        }
        this.constant_pool[i] = cp;
    }
    for (var i = 1; i < this.constant_pool_count; i++) {
        this.constant_pool[i].resolve();
    }
    this.access_flags = din.readUnsignedShort();
    this.this_class = din.readUnsignedShort();
    this.super_class = din.readUnsignedShort();
    this.interfaces_count = din.readUnsignedShort();
    this.interfaces = [];
    for (var i = 0; i < this.interfaces_count; i++) {
        this.interfaces[i] = din.readUnsignedShort();
    }
    this.fields_count = din.readUnsignedShort();
    this.fields = [];
    for (var i = 0; i < this.fields_count; i++) {
        this.fields[i] = new FieldInfo(this, din);
    }
    this.methods_count = din.readUnsignedShort();
    this.methods = [];
    this.method_by_name = [];
    for (var i = 0; i < this.methods_count; i++) {
        var m = new MethodInfo(this, din);
        this.methods[i] = m;
        this.method_by_name[m.full_name] = m;
    }
    this.attributes_count = din.readUnsignedShort();
    this.attributes = [];
    this.attribute_by_name = [];
    for (var i = 0; i < this.attributes_count; i++) {
        var a = new Attribute(this, din);
        this.attributes[i] = a;
        this.attribute_by_name[a.attribute_name] = a;
    }

    if (din.remaining() > 0) {
        print("Unexpected extra data: " + din.remaining());
    }

    this.this_class = this.constant_pool[this.this_class];
    this.super_class = this.constant_pool[this.super_class];
    for (var i = 0; i < this.interfaces_count; i++) {
        this.interfaces[i] = this.constant_pool[this.interfaces[i]];
    }

    this.dump = function() {
        print("magic:", this.magic);
        print("minor_version:", this.minor_version);
        print("major_version:", this.major_version);
        print("constant_pool_count:", this.constant_pool_count);
        for (var i = 1; i < this.constant_pool_count; i++) {
            print("  " + i, this.constant_pool[i]);
        }
        print("access_flags:", this.access_flags);
        print("this_class:", this.this_class);
        print("super_class:", this.super_class);
        print("interfaces_count:", this.interfaces_count);
        for (var i = 0; i < this.interfaces_count; i++) {
            print("  " + i, this.interfaces[i]);
        }
        print("fields_count:", this.fields_count);
        for (var i = 0; i < this.fields_count; i++) {
            this.fields[i].dump();
        }
        print("methods_count:", this.methods_count);
        for (var i = 0; i < this.methods_count; i++) {
            this.methods[i].dump();
        }
        print("attributes_count:", this.attributes_count);
        for (var i = 0; i < this.attributes_count; i++) {
            this.attributes[i].dump();
        }
    }

    this.exec = function(env, method, obj, args) {
        var m = this.method_by_name[method];
        if (m === undefined) {
            var name = method.substr(0, method.indexOf("("));
            if (name in obj) {
                var jsargs = [];
                for (var i = 0; i < args.length; i++) {
                    if (args[i].classref === java_lang_String) {
                        jsargs[i] = args[i].s;
                    } else {
                        jsargs[i] = args[i];
                    }
                }
                return obj[name].apply(obj, jsargs);
            }
            throw ("Undefined method: " + method);
        }
        var code = m.attribute_by_name["Code"].attr.code;
        var pc = 0;
        while (true) {
            var op = code[pc][0];
            pc = Opcode[op](this, env, code[pc], pc);
            if (pc === undefined) {
                throw ("Unimplemented opcode: " + op);
            }
            if (pc < 0) {
                break;
            }
        }
    }
}

function getField(obj, name) {
    return obj[name];
}

function java_lang_String() {
    this.newInstance = function(s) {
        return new function() {
            this.classref = java_lang_String;
            this.s = s;
        };
    }
}

function java_lang_System() {
    this.err = null;
    this["in"] = null;
    this.out = null;
}

function SystemClassLoader() {
    this.classes = [];

    this.getClass = function(name) {
        var c = this.classes[name];
        if (c !== undefined) {
            return c;
        }
        switch (name) {
            case "java/lang/String": c = new java_lang_String(); break;
            case "java/lang/System": c = new java_lang_System(); break;
            default:
                throw ("Unknown system class: " + name);
        }
        if (c !== undefined) {
            this.classes[name] = c;
        }
        return c;
    }
}

function FileClassLoader(parent) {
    defineClass("FileLoader");
    this.parent = parent;
    this.classes = [];

    this.getClass = function(name) {
        var c = this.classes[name];
        if (c !== undefined) {
            return c;
        }
        var f;
        try {
            f = new FileLoader(name + ".class");
        } catch (e) {
            return this.parent.getClass(name);
        }
        c = new Class(this, f.readAll());
        this.classes[name] = c;
        return c;
    }
}

function Environment() {
    this.stack = [];
    this.index = 0;

    this.pop = function() {
        return this.stack[--this.index];
    }

    this.push = function(x) {
        this.stack[this.index++] = x;
    }

    this.top = function() {
        return this.stack[this.index - 1];
    }
}

function ConsolePrintStream() {
    this.println = function(s) {
        print(s);
    }
}

var scl = new SystemClassLoader();
var jls = scl.getClass("java/lang/System");
jls.out = new ConsolePrintStream();
var fcl = new FileClassLoader(scl);
var c = fcl.getClass(arguments[0]);
//c.dump();
var env = new Environment();
c.exec(env, "main([Ljava/lang/String;)V", null, []);
