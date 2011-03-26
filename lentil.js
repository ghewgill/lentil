var DEBUG_LOAD_CLASS = false;
var DEBUG_METHOD_CALLS = false;
var DEBUG_NEW_INSTANCE = false;
var DEBUG_SHOW_DISASSEMBLY = false;
var DEBUG_TRACE_STACK = false;
var DEBUG_TRACE_DISASSEMBLE = false;

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

var T_BOOLEAN =  4;
var T_CHAR    =  5;
var T_FLOAT   =  6;
var T_DOUBLE  =  7;
var T_BYTE    =  8;
var T_SHORT   =  9;
var T_INT     = 10;
var T_LONG    = 11;

var ArrayTypeChar = {};
ArrayTypeChar[T_BOOLEAN] = "Z";
ArrayTypeChar[T_CHAR   ] = "C";
ArrayTypeChar[T_FLOAT  ] = "F";
ArrayTypeChar[T_DOUBLE ] = "D";
ArrayTypeChar[T_BYTE   ] = "B";
ArrayTypeChar[T_SHORT  ] = "S";
ArrayTypeChar[T_INT    ] = "I";
ArrayTypeChar[T_LONG   ] = "J";

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

OpcodeName = [
    "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1",
    "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0",
    "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0",
    "dconst_1", "bipush", "sipush", "ldc", "ldc_w", "ldc2_w",
    "iload", "lload", "fload", "dload", "aload", "iload_0",
    "iload_1", "iload_2", "iload_3", "lload_0", "lload_1",
    "lload_2", "lload_3", "fload_0", "fload_1", "fload_2",
    "fload_3", "dload_0", "dload_1", "dload_2", "dload_3",
    "aload_0", "aload_1", "aload_2", "aload_3", "iaload",
    "laload", "faload", "daload", "aaload", "baload", "caload",
    "saload", "istore", "lstore", "fstore", "dstore", "astore",
    "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0",
    "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1",
    "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2",
    "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3",
    "iastore", "lastore", "fastore", "dastore", "aastore",
    "bastore", "castore", "sastore", "pop", "pop2", "dup",
    "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
    "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub",
    "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv",
    "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg",
    "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr",
    "iushr", "lushr", "iand", "land", "ior", "lor", "ixor",
    "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f",
    "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f",
    "i2b", "i2c", "i2s", "lcmp", "fcmpl",
    "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge",
    "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt",
    "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne",
    "goto", "jsr", "ret", "tableswitch", "lookupswitch",
    "ireturn", "lreturn", "freturn", "dreturn", "areturn",
    "return", "getstatic", "putstatic", "getfield", "putfield",
    "invokevirtual", "invokespecial", "invokestatic",
    "invokeinterface", "op_186", "new", "newarray", "anewarray",
    "arraylength", "athrow", "checkcast", "instanceof",
    "monitorenter", "monitorexit", "wide", "multianewarray",
    "ifnull", "ifnonnull", "goto_w", "jsr_w", "breakpoint",
    "op_203", "op_204", "op_205", "op_206", "op_207", "ret_w"
];

var ClassesToLink = [];
var JClass;
var JString;
var CurrentThread;

NativeMethod = {
    "java/lang/Object": {
        "hashCode": function(env) {
            return 1;
        }
    },
    "java/lang/VMClass": {
        "getClassLoader(Ljava/lang/Class;)Ljava/lang/ClassLoader;": function(env, c) {
            return null; // TODO
        },
        "getName(Ljava/lang/Class;)Ljava/lang/String;": function(env, c) {
            return internString(c.vmdata.name);
        },
        "isArray(Ljava/lang/Class;)Z": function(env, c) {
            return c.vmdata instanceof JArray;
        },
        "isPrimitive(Ljava/lang/Class;)Z": function(env, c) {
            return false; // TODO
        }
    },
    "java/lang/VMClassLoader": {
        "getBootPackages()[Ljava/lang/String;": function(env) {
            return null;
        },
        "getPrimitiveClass(C)Ljava/lang/Class;": function(env, c) {
            return {"primitive_class": c};
        }
    },
    "java/lang/VMObject": {
        "clone(Ljava/lang/Cloneable;)Ljava/lang/Object;": function(env, obj) {
            var r = {};
            for (p in obj) {
                r[p] = obj[p];
            }
            return r;
        },
        "getClass(Ljava/lang/Object;)Ljava/lang/Class;": function(env, obj) {
            return obj.__jvm_class;
        }
    },
    "java/lang/VMSystem": {
        "arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V": function(env, src, srcStart, dest, destStart, len) {
            if (src === null || dest === null) {
                throw ("null pointer exception");
            }
            if ((!src instanceof JArray && dest instanceof JArray)) {
                throw ("arraycopy with not arrays");
            }
            if (len < 0 || srcStart < 0 || srcStart + len > src.len() || destStart < 0 || destStart + len > dest.len()) {
                throw ("index out of bounds");
            }
            if (src.__jvm_class.name !== dest.__jvm_class.name) {
                throw ("incompatible arrays: " + src.__jvm_class.name + " " + dest.__jvm_class.name);
            }
            if (src.s !== undefined && dest.s !== undefined) {
                var t = src.s.substr(srcStart, len);
                dest.s = dest.s.substring(0, destStart) + t + dest.s.substring(destStart + len);
            } else {
                var t = src.a.slice(srcStart, srcStart + len);
                for (var i = 0; i < len; i++) {
                    dest.a[destStart + i] = t[i];
                }
            }
        },
        "identityHashCode(Ljava/lang/Object;)I": function(env, obj) {
            // TODO: return id(obj);
            return 1;
        }
    },
    "java/lang/VMThread": {
        "currentThread()Ljava/lang/Thread;": function(env) {
            return env.thread;
        }
    },
    "java/lang/VMThrowable": {
        "fillInStackTrace(Ljava/lang/Throwable;)Ljava/lang/VMThrowable;": function(env, t) {
            return null;
        }
    },
    "gnu/classpath/VMSystemProperties": {
        "preInit(Ljava/util/Properties;)V": function(env, p) {
            var sp = {
                "java.version"                  : "Java version number",
                "java.vendor"                   : "Java vendor specific string",
                "java.vendor.url"               : "Java vendor URL",
                "java.home"                     : "Java installation directory",
                "java.vm.specification.version" : "VM Spec version",
                "java.vm.specification.vendor"  : "VM Spec vendor",
                "java.vm.specification.name"    : "VM Spec name",
                "java.vm.version"               : "VM implementation version",
                "java.vm.vendor"                : "VM implementation vendor",
                "java.vm.name"                  : "VM implementation name",
                "java.specification.version"    : "Java Runtime Environment version",
                "java.specification.vendor"     : "Java Runtime Environment vendor",
                "java.specification.name"       : "Java Runtime Environment name",
                "java.class.version"            : "Java class version number",
                "java.class.path"               : "Java classpath",
                "java.library.path"             : "Path for finding Java libraries",
                "java.io.tmpdir"                : "Default temp file path",
                "java.compiler"                 : "Name of JIT to use",
                "java.ext.dirs"                 : "Java extension path",
                "os.name"                       : "Operating System Name",
                "os.arch"                       : "Operating System Architecture",
                "os.version"                    : "Operating System Version",
                "file.separator"                : "File separator (\"/\" on Unix)",
                "path.separator"                : "Path separator (\":\" on Unix)",
                "line.separator"                : "\n",
                "user.name"                     : "User account name",
                "user.home"                     : "User home directory",
                "user.dir"                      : "User's current working directory",
                "gnu.cpu.endian"                : "\"big\" or \"little\""
            };
            for (var k in sp) {
                runMethod(null, p.__jvm_class, "setProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;", 0, p, [internString(k), internString(sp[k])], [1, 1]);
            }
        }
    },
    "gnu/java/nio/VMChannel": {
        "initIDs()V": function(env) {
        },
        "stdin_fd()I": function(env) {
            return 0;
        },
        "stdout_fd()I": function(env) {
            return 1;
        },
        "stderr_fd()I": function(env) {
            return 2;
        },
        "write(ILjava/nio/ByteBuffer;)I": function(env, fd, buffer) {
            importClass(java.lang.System);
            System.out.print(buffer.backing_buffer.a.slice(buffer.position, buffer.limit));
            return buffer.limit - buffer.position;
        }
    }
}

function indent(i) {
    var r = "";
    while (i--) {
        r += " ";
    }
    return r;
}

function ClassError(msg) {
    this.name = "ClassError";
    this.message = msg;
}

function DataInput(bytes) {
    this.data = bytes;
    this.index = 0;

    this.readBytes = function(n) {
        var r = this.data.substr(this.index, n);
        this.index += n;
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

    this.readUnsignedLong = function() {
        return this.readN(8); // TODO: loss of precision
    }

    this.readUnsignedShort = function() {
        return this.readN(2);
    }

    this.readN = function(n) {
        var r = 0;
        while (n > 0) {
            r = (r << 8) | (this.data.charCodeAt(this.index) & 0xff);
            this.index++;
            n--;
        }
        return r;
    }

    this.remaining = function() {
        return this.data.length - this.index;
    }
}

function dump(x, indent) {
    if (indent === undefined) {
        indent = "  ";
    }
    var r = "";
    if (x === undefined) {
        r += "undefined";
    } else if (x === null) {
        r += "null";
    } else if (typeof(x) === "function") {
        r += "function";
    } else if (typeof(x) === "object") {
        r += "\n";
        for (var p in x) {
            v = x[p];
            r += indent + p + ": ";
            if (p === "__jvm_class") {
                r += v;
            } else {
                r += dump(v, indent + "    ");
            }
            r += "\n";
        }
    } else {
        r = "(" + typeof(x) + ") " + x;
    }
    return r;
}

function s8(data, index) {
    var b = data.charCodeAt(index);
    if (b & 0x80) {
        return (b & 0x7f) - 0x80;
    } else {
        return b;
    }
}

function u16(data, index) {
    var hi = data.charCodeAt(index);
    var lo = data.charCodeAt(index + 1);
    return (hi << 8) | lo;
}

function s16(data, index) {
    var hi = data.charCodeAt(index);
    var lo = data.charCodeAt(index + 1);
    if (hi & 0x80) {
        return (((hi & 0x7f) << 8) | lo) - 0x8000;
    } else {
        return (hi << 8) | lo;
    }
}

function s32(data, index) {
    var b0 = data.charCodeAt(index    );
    var b1 = data.charCodeAt(index + 1);
    var b2 = data.charCodeAt(index + 2);
    var b3 = data.charCodeAt(index + 3);
    if (b0 & 0x80) {
        return (((b0 & 0x7f) << 24) | (b1 << 16) | (b2 << 8) | b3) - 0x80000000;
    } else {
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }
}

function x8(x) {
    if (x & 0x80) {
        return -0x80 + (x & 0x7f);
    } else {
        return x & 0x7f;
    }
}

function x16(x) {
    if (x & 0x8000) {
        return -0x8000 + (x & 0x7fff);
    } else {
        return x & 0x7fff;
    }
}

function x32(x) {
    if (x & 0x80000000) {
        return -0x80000000 + (x & 0x7fffffff);
    } else {
        return x & 0x7fffffff;
    }
}

function x64(x) {
    return x;
    // TODO: need real 64-bit integer implementation
    if (x & 0x8000000000000000) {
        return -0x8000000000000000 + (x & 0x7fffffffffffffff);
    } else {
        return x & 0x7fffffffffffffff;
    }
}

function fromIEEE754Single(x) {
    if (x === 0x7f800000) {
        return Number.POSITIVE_INFINITY;
    } else if (x === 0xff800000) {
        return Number.NEGATIVE_INFINITY;
    } else if ((x >= 0x7f800001 && x <= 0x7fffffff) || (x >= 0xff800001 && x <= 0xffffffff)) {
        return NaN;
    } else {
        var s = (x & 0x80000000) ? -1 : 1;
        var e = (x >> 23) & 0xff;
        var m = (e == 0) ? (x & 0x7fffff) << 1 : (x & 0x7fffff) | 0x800000;
        return s * m * Math.pow(2, e - 150);
    }
}

function fromIEEE754Double(b) {
    var b0 = b.charCodeAt(0);
    var b1 = b.charCodeAt(1);
    var b2 = b.charCodeAt(2);
    var b3 = b.charCodeAt(3);
    var b4 = b.charCodeAt(4);
    var b5 = b.charCodeAt(5);
    var b6 = b.charCodeAt(6);
    var b7 = b.charCodeAt(7);
    if (b0 === 0x7f && b1 === 0xf0 && b2 === 0 && b3 === 0 && b4 === 0 && b5 === 0 && b6 === 0 && b7 === 0) {
        return Number.POSITIVE_INFINITY;
    } else if (b0 === 0xff && b1 === 0xf0 && b2 === 0 && b3 === 0 && b4 === 0 && b5 === 0 && b6 === 0 && b7 === 0) {
        return Number.NEGATIVE_INFINITY;
    } else if ((b0 == 0x7f && b1 >= 0xf0) || (b1 == 0xff && b1 >= 0xf0)) {
        return NaN;
    } else {
        var s = (b0 & 0x80) ? -1 : 1;
        var e = ((b0 & 0x7f) << 4) | (b1 >> 4);
        var m;
        if (e == 0) {
            m = ((b1 & 0x0f) * Math.pow(2, 49)) +
                ( b2         * Math.pow(2, 41)) +
                ( b3         * Math.pow(2, 33)) +
                ( b4         * Math.pow(2, 25)) +
                ( b5         * Math.pow(2, 17)) +
                ( b6         * Math.pow(2,  9)) +
                ( b7         *          2     );
        } else {
            m =                Math.pow(2, 52)  +
                ((b1 & 0x0f) * Math.pow(2, 48)) +
                ( b2         * Math.pow(2, 40)) +
                ( b3         * Math.pow(2, 32)) +
                ( b4         * Math.pow(2, 24)) +
                ( b5         * Math.pow(2, 16)) +
                ( b6         * Math.pow(2,  8)) +
                ( b7                          );
        }
        return s * m * Math.pow(2, e - 1075);
    }
}

function disassemble1(pc, opcode) {
    var ins = OpcodeName[opcode[0]];
    for (var j = 1; j < opcode.length; j++) {
        ins += j === 1 ? "  " : ", ";
        ins += opcode[j];
    }
    print("      " + pc + " " + ins);
}

function disassemble(code) {
    for (var i = 0; i < code.length; i++) {
        disassemble1(i, code[i]);
    }
}

var Intern = {};

function internString(s) {
    var r = Intern[s];
    if (r !== undefined) {
        r.__jvm_class = JString;
        return r;
    }
    r = {};
    r.__jvm_class = JString;
    r.value = new JArray("C", s.length, 0);
    r.value.s = s;
    r.offset = 0;
    r.count = s.length;
    r.cachedHashCode = 1; // TODO
    Intern[s] = r;
    return r;
}

function ConstantClass(din) {
    this.name_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.name = cp[this.name_index].value();
        return this;
    }

    this.toString = function() {
        return "<class " + this.name + ">";
    }

    this.value = function(cl) {
        return cl.getClass(this.name).jclass;
    }
}

function ConstantDouble(din) {
    this.bytes = fromIEEE754Double(din.readBytes(8));

    this.resolve = function(cp) {
        return this;
    }

    this.toString = function() {
        return this.bytes;
    }

    this.value = function() {
        return this.bytes;
    }
}

function ConstantFieldref(din) {
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.classname = cp[this.class_index].resolve(cp).name;
        this.name_and_type = cp[this.name_and_type_index];
        return this;
    }

    this.toString = function() {
        return "<fieldref " + this.classname + " " + this.name_and_type + ">";
    }
}

function ConstantFloat(din) {
    this.bytes = fromIEEE754Single(din.readUnsignedInt());

    this.resolve = function(cp) {
        return this;
    }

    this.toString = function() {
        return this.bytes;
    }

    this.value = function() {
        return this.bytes;
    }
}

function ConstantInteger(din) {
    this.bytes = din.readUnsignedInt();

    this.resolve = function(cp) {
        return this;
    }

    this.toString = function() {
        return this.bytes;
    }

    this.value = function() {
        return this.bytes;
    }
}

function ConstantInterfaceMethodref(din) {
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.classname = cp[this.class_index].resolve(cp).name;
        this.name_and_type = cp[this.name_and_type_index];
        return this;
    }

    this.toString = function() {
        return "<interfacemethodref " + this.classname + " " + this.name_and_type + ">";
    }
}

function ConstantLong(din) {
    this.bytes = din.readUnsignedLong();

    this.resolve = function(cp) {
        return this;
    }

    this.toString = function() {
        return this.bytes;
    }

    this.value = function() {
        return this.bytes;
    }
}

function ConstantMethodref(din) {
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.classname = cp[this.class_index].resolve(cp).name;
        this.name_and_type = cp[this.name_and_type_index];
        return this;
    }

    this.toString = function() {
        return "<methodref " + this.classname + " " + this.name_and_type + ">";
    }
}

function ConstantNameAndType(din) {
    this.name_index = din.readUnsignedShort();
    this.descriptor_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.name = cp[this.name_index].value();
        this.descriptor = cp[this.descriptor_index].value();
        return this;
    }

    this.toString = function() {
        return "<nameandtype " + this.name + " " + this.descriptor + ">";
    }
}

function ConstantString(din) {
    this.string_index = din.readUnsignedShort();

    this.resolve = function(cp) {
        this.string = cp[this.string_index].value();
        return this;
    }

    this.toString = function() {
        return "<string " + this.string + ">";
    }

    this.value = function() {
        return internString(this.string);
    }
}

function ConstantUtf8(din) {
    this.length = din.readUnsignedShort();
    this.bytes = din.readBytes(this.length);

    this.resolve = function(cp) {
        return this;
    }

    this.toString = function() {
        return "<utf8 " + this.bytes + ">";
    }

    this.value = function() {
        return this.bytes;
    }
}

function ExceptionTableEntry(cls, din) {
    this.start_pc = din.readUnsignedShort();
    this.end_pc = din.readUnsignedShort();
    this.handler_pc = din.readUnsignedShort();
    this.catch_type = din.readUnsignedShort();

    this.fixup = function(pc_to_index) {
        this.start_pc = pc_to_index[this.start_pc];
        this.end_pc = pc_to_index[this.end_pc];
        this.handler_pc = pc_to_index[this.handler_pc];
    }

    this.dump = function() {
        print("      start_pc:", this.start_pc);
        print("      end_pc:", this.end_pc);
        print("      handler_pc:", this.handler_pc);
        print("      catch_type:", this.catch_type, this.catch_class);
    }
}

function LineNumberTableEntry(cls, din) {
    this.start_pc = din.readUnsignedShort();
    this.line_number = din.readUnsignedShort();

    this.fixup = function(pc_to_index) {
        this.start_pc = pc_to_index[this.start_pc];
    }

    this.dump = function() {
        print("      start_pc:", this.start_pc);
        print("      line_number:", this.line_number);
    }
}

var AttributeDecoder = {
    "Code": function(cls, din) {
        this.cls = cls;
        this.max_stack = din.readUnsignedShort();
        this.max_locals = din.readUnsignedShort();
        this.code_length = din.readUnsignedInt();
        this.code = din.readBytes(this.code_length);
        this.exception_table_length = din.readUnsignedShort();
        this.exception_table = [];
        for (var i = 0; i < this.exception_table_length; i++) {
            this.exception_table[i] = new ExceptionTableEntry(cls, din);
        }
        this.attributes_count = din.readUnsignedShort();
        this.attributes = [];
        this.attribute_by_name = {};
        for (var i = 0; i < this.attributes_count; i++) {
            var a = new Attribute(cls, din);
            this.attributes[i] = a;
            this.attribute_by_name[a.attribute_name] = a;
        }

        this.decodeBytecode = function(cp) {
            var r = [];
            var code = this.code;
            this.pc_to_index = [];
            var fixup = [];
            for (var i = 0; i < code.length; i++) {
                this.pc_to_index[i] = r.length;
                var ins;
                switch (code.charCodeAt(i)) {
                    case op_nop:
                        ins = [op_nop];
                        break;
                    case op_aconst_null:
                        ins = [op_aconst_null];
                        break;
                    case op_iconst_m1:
                        ins = [op_iconst_m1];
                        break;
                    case op_iconst_0:
                        ins = [op_iconst_0];
                        break;
                    case op_iconst_1:
                        ins = [op_iconst_1];
                        break;
                    case op_iconst_2:
                        ins = [op_iconst_2];
                        break;
                    case op_iconst_3:
                        ins = [op_iconst_3];
                        break;
                    case op_iconst_4:
                        ins = [op_iconst_4];
                        break;
                    case op_iconst_5:
                        ins = [op_iconst_5];
                        break;
                    case op_lconst_0:
                        ins = [op_lconst_0];
                        break;
                    case op_lconst_1:
                        ins = [op_lconst_1];
                        break;
                    case op_fconst_0:
                        ins = [op_fconst_0];
                        break;
                    case op_fconst_1:
                        ins = [op_fconst_1];
                        break;
                    case op_fconst_2:
                        ins = [op_fconst_2];
                        break;
                    case op_dconst_0:
                        ins = [op_dconst_0];
                        break;
                    case op_dconst_1:
                        ins = [op_dconst_1];
                        break;
                    case op_bipush:
                        ins = [op_bipush, s8(code, i+1)];
                        i += 1;
                        break;
                    case op_sipush:
                        ins = [op_sipush, s16(code, i+1)];
                        i += 2;
                        break;
                    case op_ldc:
                        ins = [op_ldc, cp[code.charCodeAt(i+1)]];
                        i += 1;
                        break;
                    case op_ldc_w:
                        ins = [op_ldc_w, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_ldc2_w:
                        ins = [op_ldc2_w, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_iload:
                        ins = [op_iload, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_lload:
                        ins = [op_lload, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_fload:
                        ins = [op_fload, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_dload:
                        ins = [op_dload, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_aload:
                        ins = [op_aload, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_iload_0:
                        ins = [op_iload, 0];
                        break;
                    case op_iload_1:
                        ins = [op_iload, 1];
                        break;
                    case op_iload_2:
                        ins = [op_iload, 2];
                        break;
                    case op_iload_3:
                        ins = [op_iload, 3];
                        break;
                    case op_lload_0:
                        ins = [op_lload, 0];
                        break;
                    case op_lload_1:
                        ins = [op_lload, 1];
                        break;
                    case op_lload_2:
                        ins = [op_lload, 2];
                        break;
                    case op_lload_3:
                        ins = [op_lload, 3];
                        break;
                    case op_fload_0:
                        ins = [op_aload, 0];
                        break;
                    case op_fload_1:
                        ins = [op_aload, 1];
                        break;
                    case op_fload_2:
                        ins = [op_aload, 2];
                        break;
                    case op_fload_3:
                        ins = [op_aload, 3];
                        break;
                    case op_dload_0:
                        ins = [op_dload, 0];
                        break;
                    case op_dload_1:
                        ins = [op_dload, 1];
                        break;
                    case op_dload_2:
                        ins = [op_dload, 2];
                        break;
                    case op_dload_3:
                        ins = [op_dload, 3];
                        break;
                    case op_aload_0:
                        ins = [op_aload, 0];
                        break;
                    case op_aload_1:
                        ins = [op_aload, 1];
                        break;
                    case op_aload_2:
                        ins = [op_aload, 2];
                        break;
                    case op_aload_3:
                        ins = [op_aload, 3];
                        break;
                    case op_iaload:
                        ins = [op_iaload];
                        break;
                    case op_laload:
                        ins = [op_laload];
                        break;
                    case op_faload:
                        ins = [op_faload];
                        break;
                    case op_daload:
                        ins = [op_daload];
                        break;
                    case op_aaload:
                        ins = [op_aaload];
                        break;
                    case op_baload:
                        ins = [op_baload];
                        break;
                    case op_caload:
                        ins = [op_caload];
                        break;
                    case op_saload:
                        ins = [op_saload];
                        break;
                    case op_istore:
                        ins = [op_istore, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_lstore:
                        ins = [op_lstore, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_fstore:
                        ins = [op_fstore, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_dstore:
                        ins = [op_dstore, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_astore:
                        ins = [op_astore, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_istore_0:
                        ins = [op_istore, 0];
                        break;
                    case op_istore_1:
                        ins = [op_istore, 1];
                        break;
                    case op_istore_2:
                        ins = [op_istore, 2];
                        break;
                    case op_istore_3:
                        ins = [op_istore, 3];
                        break;
                    case op_lstore_0:
                        ins = [op_lstore, 0];
                        break;
                    case op_lstore_1:
                        ins = [op_lstore, 1];
                        break;
                    case op_lstore_2:
                        ins = [op_lstore, 2];
                        break;
                    case op_lstore_3:
                        ins = [op_lstore, 3];
                        break;
                    case op_fstore_0:
                        ins = [op_fstore, 0];
                        break;
                    case op_fstore_1:
                        ins = [op_fstore, 1];
                        break;
                    case op_fstore_2:
                        ins = [op_fstore, 2];
                        break;
                    case op_fstore_3:
                        ins = [op_fstore, 3];
                        break;
                    case op_dstore_0:
                        ins = [op_dstore, 0];
                        break;
                    case op_dstore_1:
                        ins = [op_dstore, 1];
                        break;
                    case op_dstore_2:
                        ins = [op_dstore, 2];
                        break;
                    case op_dstore_3:
                        ins = [op_dstore, 3];
                        break;
                    case op_astore_0:
                        ins = [op_astore, 0];
                        break;
                    case op_astore_1:
                        ins = [op_astore, 1];
                        break;
                    case op_astore_2:
                        ins = [op_astore, 2];
                        break;
                    case op_astore_3:
                        ins = [op_astore, 3];
                        break;
                    case op_iastore:
                        ins = [op_iastore];
                        break;
                    case op_lastore:
                        ins = [op_lastore];
                        break;
                    case op_fastore:
                        ins = [op_fastore];
                        break;
                    case op_dastore:
                        ins = [op_dastore];
                        break;
                    case op_aastore:
                        ins = [op_aastore];
                        break;
                    case op_bastore:
                        ins = [op_bastore];
                        break;
                    case op_castore:
                        ins = [op_castore];
                        break;
                    case op_sastore:
                        ins = [op_sastore];
                        break;
                    case op_pop:
                        ins = [op_pop];
                        break;
                    case op_pop2:
                        ins = [op_pop2];
                        break;
                    case op_dup:
                        ins = [op_dup];
                        break;
                    case op_dup_x1:
                        ins = [op_dup_x1];
                        break;
                    //case op_dup_x2:
                    case op_dup2:
                        ins = [op_dup2];
                        break;
                    //case op_dup2_x1:
                    //case op_dup2_x2:
                    //case op_swap:
                    case op_iadd:
                        ins = [op_iadd];
                        break;
                    case op_ladd:
                        ins = [op_ladd];
                        break;
                    case op_fadd:
                        ins = [op_fadd];
                        break;
                    case op_dadd:
                        ins = [op_dadd];
                        break;
                    case op_isub:
                        ins = [op_isub];
                        break;
                    case op_lsub:
                        ins = [op_lsub];
                        break;
                    case op_fsub:
                        ins = [op_fsub];
                        break;
                    case op_dsub:
                        ins = [op_dsub];
                        break;
                    case op_imul:
                        ins = [op_imul];
                        break;
                    case op_lmul:
                        ins = [op_lmul];
                        break;
                    case op_fmul:
                        ins = [op_fmul];
                        break;
                    case op_dmul:
                        ins = [op_dmul];
                        break;
                    case op_idiv:
                        ins = [op_idiv];
                        break;
                    case op_ldiv:
                        ins = [op_ldiv];
                        break;
                    case op_fdiv:
                        ins = [op_fdiv];
                        break;
                    case op_ddiv:
                        ins = [op_ddiv];
                        break;
                    case op_irem:
                        ins = [op_irem];
                        break;
                    case op_lrem:
                        ins = [op_lrem];
                        break;
                    case op_frem:
                        ins = [op_frem];
                        break;
                    case op_drem:
                        ins = [op_drem];
                        break;
                    case op_ineg:
                        ins = [op_ineg];
                        break;
                    case op_lneg:
                        ins = [op_lneg];
                        break;
                    case op_fneg:
                        ins = [op_fneg];
                        break;
                    case op_dneg:
                        ins = [op_dneg];
                        break;
                    case op_ishl:
                        ins = [op_ishl];
                        break;
                    case op_lshl:
                        ins = [op_lshl];
                        break;
                    case op_ishr:
                        ins = [op_ishr];
                        break;
                    case op_lshr:
                        ins = [op_lshr];
                        break;
                    case op_iushr:
                        ins = [op_iushr];
                        break;
                    case op_lushr:
                        ins = [op_lushr];
                        break;
                    case op_iand:
                        ins = [op_iand];
                        break;
                    case op_land:
                        ins = [op_land];
                        break;
                    case op_ior:
                        ins = [op_ior];
                        break;
                    case op_lor:
                        ins = [op_lor];
                        break;
                    case op_ixor:
                        ins = [op_ixor];
                        break;
                    case op_lxor:
                        ins = [op_lxor];
                        break;
                    case op_iinc:
                        ins = [op_iinc, code.charCodeAt(i+1), s8(code, i+2)];
                        i += 2;
                        break;
                    case op_i2l:
                        ins = [op_i2l];
                        break;
                    case op_i2f:
                        ins = [op_i2f];
                        break;
                    case op_i2d:
                        ins = [op_i2d];
                        break;
                    case op_l2i:
                        ins = [op_l2i];
                        break;
                    case op_l2f:
                        ins = [op_l2f];
                        break;
                    case op_l2d:
                        ins = [op_l2d];
                        break;
                    case op_f2i:
                        ins = [op_f2i];
                        break;
                    case op_f2l:
                        ins = [op_f2l];
                        break;
                    case op_f2d:
                        ins = [op_f2d];
                        break;
                    case op_d2i:
                        ins = [op_d2i];
                        break;
                    case op_d2l:
                        ins = [op_d2l];
                        break;
                    case op_d2f:
                        ins = [op_d2f];
                        break;
                    case op_i2b:
                        ins = [op_i2b];
                        break;
                    case op_i2c:
                        ins = [op_i2c];
                        break;
                    case op_i2s:
                        ins = [op_i2s];
                        break;
                    case op_lcmp:
                        ins = [op_lcmp];
                        break;
                    case op_fcmpl:
                        ins = [op_fcmpl];
                        break;
                    case op_fcmpg:
                        ins = [op_fcmpg];
                        break;
                    case op_dcmpl:
                        ins = [op_dcmpl];
                        break;
                    case op_dcmpg:
                        ins = [op_dcmpg];
                        break;
                    case op_ifeq:
                        ins = [op_ifeq, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ifne:
                        ins = [op_ifne, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_iflt:
                        ins = [op_iflt, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ifge:
                        ins = [op_ifge, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ifgt:
                        ins = [op_ifgt, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ifle:
                        ins = [op_ifle, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmpeq:
                        ins = [op_if_icmpeq, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmpne:
                        ins = [op_if_icmpne, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmplt:
                        ins = [op_if_icmplt, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmpge:
                        ins = [op_if_icmpge, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmpgt:
                        ins = [op_if_icmpgt, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_icmple:
                        ins = [op_if_icmple, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_acmpeq:
                        ins = [op_if_acmpeq, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_if_acmpne:
                        ins = [op_if_acmpne, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_goto:
                        ins = [op_goto, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_jsr:
                        ins = [op_jsr, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ret:
                        ins = [op_ret, code.charCodeAt(i+1)];
                        i += 1;
                        break;
                    case op_tableswitch:
                        var j = (i + 4) & ~3;
                        var def = i + s32(code, j);
                        j += 4;
                        var low = s32(code, j);
                        j += 4;
                        var high = s32(code, j);
                        j += 4;
                        ins = [op_tableswitch, def, low, high];
                        for (k = low; k <= high; k++) {
                            ins.push(i + s32(code, j));
                            j += 4;
                        }
                        fixup.push(r.length);
                        i = j - 1;
                        break;
                    case op_lookupswitch:
                        var j = (i + 4) & ~3;
                        var def = i + s32(code, j);
                        j += 4;
                        var npairs = s32(code, j);
                        j += 4;
                        ins = [op_lookupswitch, def, []];
                        while (npairs--) {
                            var match = s32(code, j);
                            j += 4;
                            var offset = i + s32(code, j);
                            j += 4;
                            ins[2][match] = offset;
                        }
                        fixup.push(r.length);
                        i = j - 1;
                        break;
                    case op_ireturn:
                        ins = [op_ireturn];
                        break;
                    case op_lreturn:
                        ins = [op_lreturn];
                        break;
                    case op_freturn:
                        ins = [op_freturn];
                        break;
                    case op_dreturn:
                        ins = [op_dreturn];
                        break;
                    case op_areturn:
                        ins = [op_areturn];
                        break;
                    case op_return:
                        ins = [op_return];
                        break;
                    case op_getstatic:
                        ins = [op_getstatic, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_putstatic:
                        ins = [op_putstatic, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_getfield:
                        ins = [op_getfield, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_putfield:
                        ins = [op_putfield, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_invokevirtual:
                        ins = [op_invokevirtual, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_invokespecial:
                        ins = [op_invokespecial, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_invokestatic:
                        ins = [op_invokestatic, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_invokeinterface:
                        ins = [op_invokeinterface, cp[u16(code, i+1)]];
                        i += 4;
                        break;
                    case op_new:
                        ins = [op_new, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_newarray:
                        ins = [op_newarray, ArrayTypeChar[code.charCodeAt(i+1)]];
                        i += 1;
                        break;
                    case op_anewarray:
                        ins = [op_anewarray, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_arraylength:
                        ins = [op_arraylength];
                        break;
                    case op_athrow:
                        ins = [op_athrow];
                        break;
                    case op_checkcast:
                        ins = [op_checkcast, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_instanceof:
                        ins = [op_instanceof, cp[u16(code, i+1)]];
                        i += 2;
                        break;
                    case op_monitorenter:
                        ins = [op_monitorenter];
                        break;
                    case op_monitorexit:
                        ins = [op_monitorexit];
                        break;
                    //case op_wide:
                    case op_multianewarray:
                        ins = [op_multianewarray, cp[u16(code, i+1)], code.charCodeAt(i+3)];
                        i += 3;
                        break;
                    case op_ifnull:
                        ins = [op_ifnull, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    case op_ifnonnull:
                        ins = [op_ifnonnull, i + s16(code, i+1)];
                        fixup.push(r.length);
                        i += 2;
                        break;
                    //case op_goto_w:
                    //case op_jsr_w:
                    //case op_breakpoint:
                    //case op_ret_w:
                    default:
                        throw ("Unknown opcode: " + code.charCodeAt(i) + " " + OpcodeName[code.charCodeAt(i)]);
                }
                r.push(ins);
            }
            for (var i = 0; i < fixup.length; i++) {
                switch (r[fixup[i]][0]) {
                    case op_tableswitch:
                        r[fixup[i]][1] = this.pc_to_index[r[fixup[i]][1]];
                        for (var j = 4; j < r[fixup[i]].length; j++) {
                            r[fixup[i]][j] = this.pc_to_index[r[fixup[i]][j]];
                        }
                        break;
                    case op_lookupswitch:
                        r[fixup[i]][1] = this.pc_to_index[r[fixup[i]][1]];
                        for (j in r[fixup[i]][2]) {
                            r[fixup[i]][2][j] = this.pc_to_index[r[fixup[i]][2][j]];
                        }
                        break;
                    default:
                        r[fixup[i]][1] = this.pc_to_index[r[fixup[i]][1]];
                        break;
                }
            }
            this.code = r;
        }

        this.dump = function() {
            print("    max_stack:", this.max_stack);
            print("    max_locals:", this.max_locals);
            print("    code_length:", this.code_length);
            //disassemble(this.code);
            print("    exception_table_length:", this.exception_table_length);
            for (var i = 0; i < this.exception_table_length; i++) {
                this.exception_table[i].dump();
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
    "LineNumberTable": function(cls, din) {
        this.cls = cls;
        this.line_number_table_length = din.readUnsignedShort();
        this.line_number_table = [];
        for (var i = 0; i < this.line_number_table_length; i++) {
            this.line_number_table[i] = new LineNumberTableEntry(cls, din);
        }

        this.fixup = function(pc_to_index) {
            for (var i = 0; i < this.line_number_table_length; i++) {
                this.line_number_table[i].fixup(pc_to_index);
            }
        }

        this.dump = function() {
            print("    line_number_table");
            for (var i = 0; i < this.line_number_table_length; i++) {
                this.line_number_table[i].dump();
            }
        }
    },
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

    var name = cls.constant_pool[this.attribute_name_index].value();
    if (name in AttributeDecoder) {
        this.attr = new AttributeDecoder[name](cls, new DataInput(this.info));
    } else {
        //print("Ignored attribute:", name);
    }

    this.attribute_name = cls.constant_pool[this.attribute_name_index].value();

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

    this.name = cls.constant_pool[this.name_index].value();
    this.descriptor = cls.constant_pool[this.descriptor_index].value();

    this.dump = function() {
        print("  access_flags:", this.access_flags);
        print("  name:", this.name_index, this.name);
        print("  descriptor:", this.descriptor_index, this.descriptor);
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

    this.name = cls.constant_pool[this.name_index].value();
    this.descriptor = cls.constant_pool[this.descriptor_index].value();
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

function defaultValue(descriptor) {
    switch (descriptor.charAt(0)) {
        case 'B': return 0;
        case 'C': return 0;
        case 'D': return 0;
        case 'F': return 0;
        case 'I': return 0;
        case 'J': return 0;
        case 'S': return 0;
        case 'Z': return 0;
        case '[': return null;
        case 'L': return null;
        default:
            throw ("Unknown descriptor character: " + descriptor);
    }
}

Opcode = [
    
    // op_nop
    function(cls, env, ins, pc) {
    },
    
    // op_aconst_null
    function(cls, env, ins, pc) {
        env.push1(null);
        return pc + 1;
    },
    
    // op_iconst_m1
    function(cls, env, ins, pc) {
        env.push1(-1);
        return pc + 1;
    },
    
    // op_iconst_0
    function(cls, env, ins, pc) {
        env.push1(0);
        return pc + 1;
    },
    
    // op_iconst_1
    function(cls, env, ins, pc) {
        env.push1(1);
        return pc + 1;
    },
    
    // op_iconst_2
    function(cls, env, ins, pc) {
        env.push1(2);
        return pc + 1;
    },
    
    // op_iconst_3
    function(cls, env, ins, pc) {
        env.push1(3);
        return pc + 1;
    },
    
    // op_iconst_4
    function(cls, env, ins, pc) {
        env.push1(4);
        return pc + 1;
    },
    
    // op_iconst_5
    function(cls, env, ins, pc) {
        env.push1(5);
        return pc + 1;
    },
    
    // op_lconst_0
    function(cls, env, ins, pc) {
        env.push2(0);
        return pc + 1;
    },
    
    // op_lconst_1
    function(cls, env, ins, pc) {
        env.push2(1);
        return pc + 1;
    },
    
    // op_fconst_0
    function(cls, env, ins, pc) {
        env.push1(0);
        return pc + 1;
    },
    
    // op_fconst_1
    function(cls, env, ins, pc) {
        env.push1(1);
        return pc + 1;
    },
    
    // op_fconst_2
    function(cls, env, ins, pc) {
        env.push1(2);
        return pc + 1;
    },
    
    // op_dconst_0
    function(cls, env, ins, pc) {
        env.push2(0);
        return pc + 1;
    },
    
    // op_dconst_1
    function(cls, env, ins, pc) {
        env.push2(1);
        return pc + 1;
    },
    
    // op_bipush
    function(cls, env, ins, pc) {
        env.push1(ins[1]);
        return pc + 1;
    },
    
    // op_sipush
    function(cls, env, ins, pc) {
        env.push1(ins[1]);
        return pc + 1;
    },
    
    // op_ldc
    function(cls, env, ins, pc) {
        env.push1(ins[1].value());
        return pc + 1;
    },
    
    // op_ldc_w
    function(cls, env, ins, pc) {
        env.push1(ins[1].value(cls.classloader));
        return pc + 1;
    },
    
    // op_ldc2_w
    function(cls, env, ins, pc) {
        env.push2(ins[1].value());
        return pc + 1;
    },
    
    // op_iload
    function(cls, env, ins, pc) {
        env.push1(env.local[ins[1]]);
        return pc + 1;
    },
    
    // op_lload
    function(cls, env, ins, pc) {
        env.push2(env.local[ins[1]]);
        return pc + 1;
    },
    
    // op_fload
    function(cls, env, ins, pc) {
        env.push1(env.local[ins[1]]);
        return pc + 1;
    },
    
    // op_dload
    function(cls, env, ins, pc) {
        env.push2(env.local[ins[1]]);
        return pc + 1;
    },
    
    // op_aload
    function(cls, env, ins, pc) {
        env.push1(env.local[ins[1]]);
        return pc + 1;
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
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_laload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push2(a.load(index));
        return pc + 1;
    },
    
    // op_faload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_daload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push2(a.load(index));
        return pc + 1;
    },
    
    // op_aaload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_baload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_caload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_saload
    function(cls, env, ins, pc) {
        var index = env.pop();
        var a = env.pop();
        env.push1(a.load(index));
        return pc + 1;
    },
    
    // op_istore
    function(cls, env, ins, pc) {
        env.local[ins[1]] = env.pop();
        return pc + 1;
    },
    
    // op_lstore
    function(cls, env, ins, pc) {
        env.local[ins[1]] = env.pop();
        return pc + 1;
    },
    
    // op_fstore
    function(cls, env, ins, pc) {
        env.local[ins[1]] = env.pop();
        return pc + 1;
    },
    
    // op_dstore
    function(cls, env, ins, pc) {
        env.local[ins[1]] = env.pop();
        return pc + 1;
    },
    
    // op_astore
    function(cls, env, ins, pc) {
        env.local[ins[1]] = env.pop();
        return pc + 1;
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
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_lastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_fastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_dastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_aastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_bastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_castore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_sastore
    function(cls, env, ins, pc) {
        var value = env.pop();
        var index = env.pop();
        var a = env.pop();
        a.store(index, value);
        return pc + 1;
    },
    
    // op_pop
    function(cls, env, ins, pc) {
        env.pop();
        return pc + 1;
    },
    
    // op_pop2
    function(cls, env, ins, pc) {
        // TODO: must figure out whether top is a cat1 or cat2 type
        // for now, assume single cat2 value
        env.pop();
        return pc + 1;
    },
    
    // op_dup
    function(cls, env, ins, pc) {
        env.push1(env.top());
        return pc + 1;
    },
    
    // op_dup_x1
    function(cls, env, ins, pc) {
        var v1 = env.pop();
        var v2 = env.pop();
        env.push1(v1);
        env.push1(v2);
        env.push1(v1);
        return pc + 1;
    },
    
    // op_dup_x2
    function(cls, env, ins, pc) {
    },
    
    // op_dup2
    function(cls, env, ins, pc) {
        if (env.topcat() == 2) {
            env.push2(env.top());
        } else {
            var v1 = env.pop();
            var v2 = env.top();
            env.push1(v1);
            env.push1(v2);
            env.push1(v1);
        }
        return pc + 1;
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
        var y = env.pop();
        var x = env.pop();
        env.push1(x32(x + y));
        return pc + 1;
    },
    
    // op_ladd
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x64(x + y));
        return pc + 1;
    },
    
    // op_fadd
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x + y);
        return pc + 1;
    },
    
    // op_dadd
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x + y);
        return pc + 1;
    },
    
    // op_isub
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x32(x - y));
        return pc + 1;
    },
    
    // op_lsub
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x64(x - y));
        return pc + 1;
    },
    
    // op_fsub
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x - y);
        return pc + 1;
    },
    
    // op_dsub
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x - y);
        return pc + 1;
    },
    
    // op_imul
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x32(x * y));
        return pc + 1;
    },
    
    // op_lmul
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x64(x * y));
        return pc + 1;
    },
    
    // op_fmul
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x * y);
        return pc + 1;
    },
    
    // op_dmul
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x * y);
        return pc + 1;
    },
    
    // op_idiv
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x32(x / y));
        return pc + 1;
    },
    
    // op_ldiv
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x32(x / y));
        return pc + 1;
    },
    
    // op_fdiv
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x / y);
        return pc + 1;
    },
    
    // op_ddiv
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x / y);
        return pc + 1;
    },
    
    // op_irem
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x32(x % y));
        return pc + 1;
    },
    
    // op_lrem
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x64(x % y));
        return pc + 1;
    },
    
    // op_frem
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x % y);
        return pc + 1;
    },
    
    // op_drem
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x % y);
        return pc + 1;
    },
    
    // op_ineg
    function(cls, env, ins, pc) {
        env.push1(-env.pop());
        return pc + 1;
    },
    
    // op_lneg
    function(cls, env, ins, pc) {
        env.push2(-env.pop());
        return pc + 1;
    },
    
    // op_fneg
    function(cls, env, ins, pc) {
        env.push1(-env.pop());
        return pc + 1;
    },
    
    // op_dneg
    function(cls, env, ins, pc) {
        env.push2(-env.pop());
        return pc + 1;
    },
    
    // op_ishl
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x << (y & 0x1f));
        return pc + 1;
    },
    
    // op_lshl
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x << (y & 0x1f));
        return pc + 1;
    },
    
    // op_ishr
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x >> (y & 0x1f));
        return pc + 1;
    },
    
    // op_lshr
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x >> (y & 0x1f));
        return pc + 1;
    },
    
    // op_iushr
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x >>> (y & 0x1f));
        return pc + 1;
    },
    
    // op_lushr
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x >>> (y & 0x1f));
        return pc + 1;
    },
    
    // op_iand
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x & y);
        return pc + 1;
    },
    
    // op_land
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x & y);
        return pc + 1;
    },
    
    // op_ior
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x | y);
        return pc + 1;
    },
    
    // op_lor
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x | y);
        return pc + 1;
    },
    
    // op_ixor
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push1(x ^ y);
        return pc + 1;
    },
    
    // op_lxor
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        env.push2(x ^ y);
        return pc + 1;
    },
    
    // op_iinc
    function(cls, env, ins, pc) {
        env.local[ins[1]] += ins[2];
        return pc + 1;
    },
    
    // op_i2l
    function(cls, env, ins, pc) {
        env.push2(env.pop());
        return pc + 1;
    },
    
    // op_i2f
    function(cls, env, ins, pc) {
        return pc + 1;
    },
    
    // op_i2d
    function(cls, env, ins, pc) {
        env.push2(env.pop());
        return pc + 1;
    },
    
    // op_l2i
    function(cls, env, ins, pc) {
        env.push1(x32(env.pop() & 0xffffffff));
        return pc + 1;
    },
    
    // op_l2f
    function(cls, env, ins, pc) {
        env.push1(env.pop());
        return pc + 1;
    },
    
    // op_l2d
    function(cls, env, ins, pc) {
        return pc + 1;
    },
    
    // op_f2i
    function(cls, env, ins, pc) {
        env.push1(env.pop() | 0);
        return pc + 1;
    },
    
    // op_f2l
    function(cls, env, ins, pc) {
        env.push2(env.pop() | 0);
        return pc + 1;
    },
    
    // op_f2d
    function(cls, env, ins, pc) {
        env.push2(env.pop());
        return pc + 1;
    },
    
    // op_d2i
    function(cls, env, ins, pc) {
        env.push1(env.pop() | 0);
        return pc + 1;
    },
    
    // op_d2l
    function(cls, env, ins, pc) {
        env.push2(env.pop() | 0);
        return pc + 1;
    },
    
    // op_d2f
    function(cls, env, ins, pc) {
        env.push1(env.pop());
        return pc + 1;
    },
    
    // op_i2b
    function(cls, env, ins, pc) {
        env.push1(x8(env.pop() & 0xff));
        return pc + 1;
    },
    
    // op_i2c
    function(cls, env, ins, pc) {
        env.push1(env.pop() & 0xffff);
        return pc + 1;
    },
    
    // op_i2s
    function(cls, env, ins, pc) {
        env.push1(x16(env.pop() & 0xffff));
        return pc + 1;
    },
    
    // op_lcmp
    function(cls, env, ins, pc) {
        var v2 = env.pop();
        var v1 = env.pop();
        if (v1 == v2) {
            env.push1(0);
        } else if (v1 > v2) {
            env.push1(1);
        } else {
            env.push1(-1);
        }
        return pc + 1;
    },
    
    // op_fcmpl
    function(cls, env, ins, pc) {
        var v2 = env.pop();
        var v1 = env.pop();
        if (v1 == v2) {
            env.push1(0);
        } else if (v1 > v2) {
            env.push1(1);
        } else if (v1 < v2) {
            env.push1(-1);
        } else {
            env.push1(-1);
        }
        return pc + 1;
    },
    
    // op_fcmpg
    function(cls, env, ins, pc) {
        var v2 = env.pop();
        var v1 = env.pop();
        if (v1 == v2) {
            env.push1(0);
        } else if (v1 > v2) {
            env.push1(1);
        } else if (v1 < v2) {
            env.push1(-1);
        } else {
            env.push1(1);
        }
        return pc + 1;
    },
    
    // op_dcmpl
    function(cls, env, ins, pc) {
        var v2 = env.pop();
        var v1 = env.pop();
        if (v1 == v2) {
            env.push1(0);
        } else if (v1 > v2) {
            env.push1(1);
        } else if (v1 < v2) {
            env.push1(-1);
        } else {
            env.push1(-1);
        }
        return pc + 1;
    },
    
    // op_dcmpg
    function(cls, env, ins, pc) {
        var v2 = env.pop();
        var v1 = env.pop();
        if (v1 == v2) {
            env.push1(0);
        } else if (v1 > v2) {
            env.push1(1);
        } else if (v1 < v2) {
            env.push1(-1);
        } else {
            env.push1(1);
        }
        return pc + 1;
    },
    
    // op_ifeq
    function(cls, env, ins, pc) {
        if (env.pop() == 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_ifne
    function(cls, env, ins, pc) {
        var x = env.pop();
        if (x != 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_iflt
    function(cls, env, ins, pc) {
        if (env.pop() < 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_ifge
    function(cls, env, ins, pc) {
        if (env.pop() >= 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_ifgt
    function(cls, env, ins, pc) {
        if (env.pop() > 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_ifle
    function(cls, env, ins, pc) {
        if (env.pop() <= 0) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmpeq
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x == y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmpne
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x != y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmplt
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x < y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmpge
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x >= y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmpgt
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x > y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_icmple
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x <= y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_acmpeq
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x === y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_if_acmpne
    function(cls, env, ins, pc) {
        var y = env.pop();
        var x = env.pop();
        if (x !== y) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_goto
    function(cls, env, ins, pc) {
        return ins[1];
    },
    
    // op_jsr
    function(cls, env, ins, pc) {
        env.push1(pc + 1);
        return ins[1];
    },
    
    // op_ret
    function(cls, env, ins, pc) {
        return env.local[ins[1]];
    },
    
    // op_tableswitch
    function(cls, env, ins, pc) {
        var x = env.pop();
        if (x >= ins[2] && x <= ins[3]) {
            return ins[4 + x - ins[2]];
        }
        return ins[1];
    },
    
    // op_lookupswitch
    function(cls, env, ins, pc) {
        var x = env.pop();
        var t = ins[2][x];
        if (t !== undefined) {
            return t;
        }
        return ins[1];
    },
    
    // op_ireturn
    function(cls, env, ins, pc) {
        // object to return is already on stack
        return -1;
    },
    
    // op_lreturn
    function(cls, env, ins, pc) {
        // object to return is already on stack
        return -1;
    },
    
    // op_freturn
    function(cls, env, ins, pc) {
        // object to return is already on stack
        return -1;
    },
    
    // op_dreturn
    function(cls, env, ins, pc) {
        // object to return is already on stack
        return -1;
    },
    
    // op_areturn
    function(cls, env, ins, pc) {
        // object to return is already on stack
        return -1;
    },
    
    // op_return
    function(cls, env, ins, pc) {
        return -1;
    },
    
    // op_getstatic
    function(cls, env, ins, pc) {
        var fr = ins[1];
        var c = cls.classloader.getClass(fr.classname);
        // TODO: cat2 field
        env.push1(c.getStatic(fr.name_and_type.name));
        return pc + 1;
    },
    
    // op_putstatic
    function(cls, env, ins, pc) {
        var fr = ins[1];
        var c = cls.classloader.getClass(fr.classname);
        c.putStatic(fr.name_and_type.name, env.pop());
        return pc + 1;
    },
    
    // op_getfield
    function(cls, env, ins, pc) {
        var fr = ins[1];
        var obj = env.pop();
        // TODO: cat2 field
        env.push1(obj[fr.name_and_type.name]);
        return pc + 1;
    },
    
    // op_putfield
    function(cls, env, ins, pc) {
        var fr = ins[1];
        var x = env.pop();
        var obj = env.pop();
        obj[fr.name_and_type.name] = x;
        return pc + 1;
    },
    
    // op_invokevirtual
    function(cls, env, ins, pc) {
        var mr = ins[1];
        var nargs = getNargs(mr.name_and_type.descriptor);
        var args = [];
        var argcats = [];
        while (nargs--) {
            argcats[nargs] = env.topcat();
            args[nargs] = env.pop();
        }
        var obj = env.pop();
        var r = startMethod(env, cls.classloader.getClass(mr.classname), mr.name_and_type.name + mr.name_and_type.descriptor, 0, obj, args, argcats);
        if (r instanceof Environment) {
            return r;
        }
        if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) != "V") {
            if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "D"
             || mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "J") {
                env.push2(r);
            } else {
                env.push1(r);
            }
        }
        return pc + 1;
    },
    
    // op_invokespecial
    function(cls, env, ins, pc) {
        var mr = ins[1];
        var nargs = getNargs(mr.name_and_type.descriptor);
        var args = [];
        var argcats = [];
        while (nargs--) {
            argcats[nargs] = env.topcat();
            args[nargs] = env.pop();
        }
        var obj = env.pop();
        var r = startMethod(env, cls.classloader.getClass(mr.classname), mr.name_and_type.name + mr.name_and_type.descriptor, ACC_PRIVATE, obj, args, argcats);
        if (r instanceof Environment) {
            return r;
        }
        if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) != "V") {
            if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "D"
             || mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "J") {
                env.push2(r);
            } else {
                env.push1(r);
            }
        }
        return pc + 1;
    },
    
    // op_invokestatic
    function(cls, env, ins, pc) {
        var mr = ins[1];
        var nargs = getNargs(mr.name_and_type.descriptor);
        var args = [];
        var argcats = [];
        while (nargs--) {
            argcats[nargs] = env.topcat();
            args[nargs] = env.pop();
        }
        var c = cls.classloader.getClass(mr.classname);
        c.initialise();
        var r = startMethod(env, c, mr.name_and_type.name + mr.name_and_type.descriptor, ACC_STATIC, null, args, argcats);
        if (r instanceof Environment) {
            return r;
        }
        if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) != "V") {
            if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "D"
             || mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "J") {
                env.push2(r);
            } else {
                env.push1(r);
            }
        }
        return pc + 1;
    },
    
    // op_invokeinterface
    function(cls, env, ins, pc) {
        var mr = ins[1];
        var nargs = getNargs(mr.name_and_type.descriptor);
        var args = [];
        var argcats = [];
        while (nargs--) {
            argcats[nargs] = env.topcat();
            args[nargs] = env.pop();
        }
        var obj = env.pop();
        var r = startMethod(env, cls.classloader.getClass(mr.classname), mr.name_and_type.name + mr.name_and_type.descriptor, 0, obj, args, argcats);
        if (r instanceof Environment) {
            return r;
        }
        if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) != "V") {
            if (mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "D"
             || mr.name_and_type.descriptor.charAt(mr.name_and_type.descriptor.length - 1) == "J") {
                env.push2(r);
            } else {
                env.push1(r);
            }
        }
        return pc + 1;
    },

    // op_186
    function(cls, env, ins, pc) {
    },
    
    // op_new
    function(cls, env, ins, pc) {
        var c = cls.classloader.getClass(ins[1].name);
        env.push1(c.newInstance());
        return pc + 1;
    },
    
    // op_newarray
    function(cls, env, ins, pc) {
        env.push1(new JArray(ins[1], env.pop(), 0));
        return pc + 1;
    },
    
    // op_anewarray
    function(cls, env, ins, pc) {
        env.push1(new JArray(ins[1], env.pop(), null));
        return pc + 1;
    },
    
    // op_arraylength
    function(cls, env, ins, pc) {
        env.push1(env.pop().len());
        return pc + 1;
    },
    
    // op_athrow
    function(cls, env, ins, pc) {
        var x = env.pop();
        var e = env;
        while (e != null) {
            var et = e.method.attribute_by_name["Code"].attr.exception_table;
            for (var i = 0; i < et.length; i++) {
                if (pc >= et[i].start_pc && pc < et[i].end_pc &&
                    (et[i].catch_class === null || x.__jvm_class.instanceOf(et[i].catch_class))) {
                    e.push1(x);
                    e.pc = et[i].handler_pc;
                    return e;
                }
            }
            e = e.parent;
            if (e === null) {
                print("uncaught exception:", x.__jvm_class);
                var lt = env.method.attribute_by_name["Code"].attr.attribute_by_name["LineNumberTable"].attr.line_number_table;
                for (var i = 0; i+1 < lt.length; i++) {
                    if (pc < lt[i+1].start_pc) {
                        print("line", lt[i].line_number);
                        break;
                    }
                }
                throw dump(x.detailMessage);
            }
            pc = e.pc;
        }
        throw ("Unhandled exception");
    },
    
    // op_checkcast
    function(cls, env, ins, pc) {
        var obj = env.top();
        // TODO
        return pc + 1;
    },
    
    // op_instanceof
    function(cls, env, ins, pc) {
        var obj = env.pop();
        if (obj === null) {
            env.push1(0);
        } else {
            // TODO
            env.push1(1);
        }
        return pc + 1;
    },
    
    // op_monitorenter
    function(cls, env, ins, pc) {
        var obj = env.pop();
        // TODO
        return pc + 1;
    },
    
    // op_monitorexit
    function(cls, env, ins, pc) {
        var obj = env.pop();
        // TODO
        return pc + 1;
    },
    
    // op_wide
    function(cls, env, ins, pc) {
    },
    
    // op_multianewarray
    function(cls, env, ins, pc) {
        var acls = ins[1];
        var d = ins[2];
        var dims = [];
        while (d--) {
            dims[d] = env.pop();
        }
        var alloc = function(i) {
            if (i >= dims.length) {
                return null;
            }
            var c = dims[i];
            var r = new JArray(acls, c, null);
            if (c > 0) {
                while (c--) {
                    r.store(c, alloc(i + 1));
                }
            }
            return r;
        };
        env.push1(alloc(0));
        return pc + 1;
    },
    
    // op_ifnull
    function(cls, env, ins, pc) {
        if (env.pop() === null) {
            return ins[1];
        }
        return pc + 1;
    },
    
    // op_ifnonnull
    function(cls, env, ins, pc) {
        if (env.pop() !== null) {
            return ins[1];
        }
        return pc + 1;
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

function ClassFile(bytes) {
    var din = new DataInput(bytes);
    this.magic = din.readInt();
    this.minor_version = din.readUnsignedShort();
    this.major_version = din.readUnsignedShort();
    this.constant_pool_count = din.readUnsignedShort();
    this.constant_pool = [];
    for (var i = 1; i < this.constant_pool_count; i++) {
        var tag = din.readUnsignedByte();
        var ofs = 0;
        var cp;
        switch (tag) {
            case CONSTANT_Utf8:                 cp = new ConstantUtf8(din);     break;
            case CONSTANT_Integer:              cp = new ConstantInteger(din);  break;
            case CONSTANT_Float:                cp = new ConstantFloat(din);    break;
            case CONSTANT_Long:                 cp = new ConstantLong(din);     ofs = 1; break;
            case CONSTANT_Double:               cp = new ConstantDouble(din);   ofs = 1; break;
            case CONSTANT_Class:                cp = new ConstantClass(din);    break;
            case CONSTANT_String:               cp = new ConstantString(din);   break;
            case CONSTANT_Fieldref:             cp = new ConstantFieldref(din); break;
            case CONSTANT_Methodref:            cp = new ConstantMethodref(din); break;
            case CONSTANT_InterfaceMethodref:   cp = new ConstantInterfaceMethodref(din); break;
            case CONSTANT_NameAndType:          cp = new ConstantNameAndType(din); break;
            default:
                throw ("Unknown constant pool tag: " + tag);
        }
        this.constant_pool[i] = cp;
        i += ofs;
    }

    for (var i = 1; i < this.constant_pool_count; i++) {
        if (this.constant_pool[i] !== undefined) {
            this.constant_pool[i].resolve(this.constant_pool);
        }
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
    for (var i = 0; i < this.methods_count; i++) {
        var m = new MethodInfo(this, din);
        this.methods[i] = m;
    }
    this.attributes_count = din.readUnsignedShort();
    this.attributes = [];
    this.attribute_by_name = {};
    for (var i = 0; i < this.attributes_count; i++) {
        var a = new Attribute(this, din);
        this.attributes[i] = a;
        this.attribute_by_name[a.attribute_name] = a;
    }

    if (din.remaining() > 0) {
        print("Unexpected extra data: " + din.remaining());
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
            print("- field");
            this.fields[i].dump();
        }
        print("methods_count:", this.methods_count);
        for (var i = 0; i < this.methods_count; i++) {
            print("- method");
            this.methods[i].dump();
        }
        print("attributes_count:", this.attributes_count);
        for (var i = 0; i < this.attributes_count; i++) {
            print("- attribute");
            this.attributes[i].dump();
        }
    }
}

function Class(classloader, bytes) {
    this.__jvm_class = this;
    this.classloader = classloader;
    this.initialised = false;

    this.classfile = new ClassFile(bytes);
    //this.classfile.dump();
}

Class.prototype.loadSuperclasses = function() {
    var cf = this.classfile;
    var cp = cf.constant_pool;
    if (cf.super_class) {
        this.classloader.getClass(cp[cf.super_class].name);
    }
    for (var i = 0; i < cf.interfaces.length; i++) {
        this.classloader.getClass(cp[cf.interfaces[i]].name);
    }
}

Class.prototype.link = function() {
    this.name = this.classfile.constant_pool[this.classfile.this_class].name;
    this.super_class = this.classfile.super_class ? this.classloader.getClass(this.classfile.constant_pool[this.classfile.super_class].name) : null;

    this.interfaces = [];
    for (var i = 0; i < this.classfile.interfaces_count; i++) {
        this.interfaces[i] = this.classloader.getClass(this.classfile.constant_pool[this.classfile.interfaces[i]].name);
    }

    this.fields = [];
    for (var i = 0; i < this.classfile.fields_count; i++) {
        this.fields[i] = {
            "name": this.classfile.constant_pool[this.classfile.fields[i].name_index].value(),
            "descriptor": this.classfile.constant_pool[this.classfile.fields[i].descriptor_index].value(),
            "access_flags": this.classfile.fields[i].access_flags
        };
    }

    this.methods = {};
    for (var i = 0; i < this.classfile.methods_count; i++) {
        (function(that, m) {
            var fn;
            if (NativeMethod[that.name]) {
                fn = NativeMethod[that.name][m.full_name];
            }
            if (fn) {
                that.methods[m.full_name] = {"thunk": function(env, cls, methodtype, obj, args, argcats) {
                    var jsargs = [env];
                    for (var i = 0; i < args.length; i++) {
                        if (args[i] && args[i].__jvm_class && args[i].__jvm_class.name === "java/lang/String") {
                            jsargs.push(args[i].value);
                        } else {
                            jsargs.push(args[i]);
                        }
                    }
                    return fn.apply(obj, jsargs);
                }};
            } else if (!(m.access_flags & ACC_NATIVE)) {
                that.methods[m.full_name] = {"thunk": function(env, cls, methodtype, obj, args, argcats) {
                    var a = m.attribute_by_name["Code"].attr;
                    a.decodeBytecode(that.classfile.constant_pool);
                    for (var i = 0; i < a.exception_table_length; i++) {
                        var e = a.exception_table[i];
                        e.fixup(a.pc_to_index);
                        if (e.catch_type > 0) {
                            e.catch_class = that.classloader.getClass(that.classfile.constant_pool[e.catch_type].name);
                        } else {
                            e.catch_class = null;
                        }
                    }
                    if (a.attribute_by_name["LineNumberTable"]) {
                        a.attribute_by_name["LineNumberTable"].attr.fixup(a.pc_to_index);
                    }
                    if (DEBUG_SHOW_DISASSEMBLY) {
                        print(that.name, m.full_name);
                        disassemble(a.code);
                    }
                    var newf = function(env, cls, methodtype, obj, args, argcats) {
                        return new Environment(env, cls, m, methodtype, obj, args, argcats);
                    };
                    that.methods[m.full_name].thunk = newf;
                    return newf(env, cls, methodtype, obj, args, argcats);
                }};
            } else {
                that.methods[m.full_name] = {"thunk": function(env, cls, methodtype, obj, args, argcats) {
                    throw ("Native method not supplied: " + that.name + " " + m.full_name);
                }};
            }
        })(this, this.classfile.methods[i]);
    }

    var c = this.super_class;
    while (c) {
        for (var m in c.methods) {
            if (this.methods[m] === undefined) {
                this.methods[m] = c.methods[m];
            }
        }
        c = c.super_class;
    }

    this.statics = [];
    for (var i = 0; i < this.fields.length; i++) {
        var f = this.fields[i];
        if (f.access_flags & ACC_STATIC) {
            this.statics[f.name] = defaultValue(f.descriptor);
        }
    }
    this.statics["$assertionsDisabled"] = !this.desiredAssertionStatus();

}

Class.prototype.initialise = function() {
    if (!this.initialised) {
        if (this.super_class) {
            this.super_class.initialise();
        }
        this.initialised = true;
        if (this.methods["<clinit>()V"]) {
            runMethod(null, this, "<clinit>()V", ACC_STATIC, null, [], []);
        }
        if (DEBUG_LOAD_CLASS) {
            print("Initialised", this.name);
        }
    }
}

Class.prototype.getStatic = function(name) {
    this.initialise();
    for (var c = this; c != null; c = c.super_class) {
        if (name in c.statics) {
            return c.statics[name];
        }
    }
    throw ("getStatic: Unknown static: " + name);
}

Class.prototype.putStatic = function(name, value) {
    this.initialise();
    for (var c = this; c != null; c = c.super_class) {
        if (name in c.statics) {
            c.statics[name] = value;
            return;
        }
    }
    throw ("putStatic: Unknown static: " + name);
}

Class.prototype.desiredAssertionStatus = function() {
    return true;
}

Class.prototype.instanceOf = function(cls) {
    if (this === cls) {
        return true;
    }
    for (var i = 0; i < this.interfaces_count; i++) {
        var iface = this.interfaces[i];
        while (true) {
            if (cls === iface) {
                return true;
            }
            if (!iface.super_class) {
                break;
            }
            iface = iface.super_class;
        }
    }
    if (this.super_class) {
        return this.super_class.instanceOf(cls);
    }
    return false;
}

Class.prototype.dump = function() {
    this.classfile.dump();
    print("name:", this.name);
    print("super_class:", this.super_class);
    print("interfaces:");
    for (var i = 0; i < this.interfaces.length; i++) {
        print("  ", this.interfaces[i]);
    }
    print("fields:");
    for (var i = 0; i < this.fields.length; i++) {
        print("  ", this.fields[i]);
    }
    print("methods:");
    for (var i = 0; i < this.methods.length; i++) {
        print("  ", this.methods[i]);
    }
}

Class.prototype.newInstance = function() {
    var cls = this;
    this.initialise();
    return new function() {
        if (DEBUG_NEW_INSTANCE) {
            print("newInstance", cls.name);
        }
        this.__jvm_class = cls;
        for (var c = cls; c != null; c = c.super_class ? cls.classloader.getClass(c.super_class.name) : null) {
            for (var i = 0; i < c.fields.length; i++) {
                var f = c.fields[i];
                if ((f.access_flags & ACC_STATIC) == 0) {
                    this[f.name] = defaultValue(f.descriptor);
                }
            }
        }
    };
}

Class.prototype.toString = function() {
    var name = this.name ? this.name : (this.classfile.constant_pool[this.classfile.this_class].name + " (not linked)");
    return "<Class " + name + ">";
}

function JArray(type, size, def) {
    this.__jvm_class = {"name": "[" + type};
    if (type === "C") {
        this.s = "";
        for (var i = 0; i < size; i++) {
            this.s += "\0";
        }

        this.len = function() {
            return this.s.length;
        }

        this.load = function(index) {
            // TODO: bounds checking
            return this.s.charCodeAt(index);
        }

        this.store = function(index, value) {
            // TODO: bounds checking
            this.s = this.s.substring(0, index) + String.fromCharCode(value) + this.s.substring(index + 1);
        }
    } else {
        this.a = new Array(size);
        for (var i = 0; i < size; i++) {
            this.a[i] = def;
        }

        this.len = function() {
            return this.a.length;
        }

        this.load = function(index) {
            // TODO: bounds checking
            return this.a[index];
        }

        this.store = function(index, value) {
            // TODO: bounds checking
            this.a[index] = value;
        }
    }
}

function FileClassLoader(classpath) {
    defineClass("FileLoader");
    this.classpath = classpath;
    this.classpath.unshift(".");
    this.classes = [];
    this.nest = 0;

    this.getClass = function(name) {
        var c = this.classes[name];
        if (c !== undefined) {
            return c;
        }
        if (DEBUG_LOAD_CLASS) {
            print(indent(this.nest*2) + "Loading", name);
            this.nest += 1;
        }
        var c = this.loadClass(name);
        this.classes[name] = c.vmdata;
        ClassesToLink.push(c.vmdata);
        while (ClassesToLink.length > 0) {
            var t = ClassesToLink.pop();
            t.loadSuperclasses();
            t.link();
        }
        if (name === "java/lang/String") {
            JString = c.vmdata;
        }
        if (DEBUG_LOAD_CLASS) {
            print(indent(this.nest*2) + "Loaded", c.name);
            this.nest -= 1;
        }
        return c.vmdata;
    }

    this.bootstrap = function() {
        var fcl = this;
        var boot = function(name) {
            if (DEBUG_LOAD_CLASS) {
                print("bootstrap:", name);
            }
            var c = fcl.loadClass(name);
            fcl.classes[name] = c;
            c.link();
            return c;
        }
        var JObject = boot("java/lang/Object");
        boot("java/io/Serializable");
        boot("java/lang/reflect/Type");
        boot("java/lang/reflect/AnnotatedElement");
        boot("java/lang/reflect/GenericDeclaration");
        boot("java/lang/VMClass");
        JClass = boot("java/lang/Class");
        var class_object = JClass.newInstance();
        runMethod(null, JClass, "<init>(Ljava/lang/Object;)V", ACC_PRIVATE, class_object, [JObject], [1]);
        var class_class = JClass.newInstance();
        runMethod(null, JClass, "<init>(Ljava/lang/Object;)V", ACC_PRIVATE, class_class, [JClass], [1]);
    }

    this.loadClass = function(name) {
        if (DEBUG_LOAD_CLASS) {
            print("loadClass", name);
        }
        var f;
        for (var i = 0; i < this.classpath.length; i++) {
            try {
                f = new FileLoader(this.classpath[i] + "/" + name + ".class");
                break;
            } catch (e) {
                // next
            }
        }
        if (f === undefined) {
            throw ("Could not find class " + name);
        }
        var c = new Class(this, f.readAll());
        f.close();
        if (JClass === undefined) {
            return c;
        }
        c.jclass = JClass.newInstance();
        runMethod(null, JClass, "<init>(Ljava/lang/Object;)V", ACC_PRIVATE, c.jclass, [c], [1]);
        return c.jclass;
     }
}

function Stack() {
    this.stack = [];
    this.cat = [];
    this.index = 0;

    this.pop = function() {
        return this.stack[--this.index];
    }

    this.push1 = function(x) {
        if (x === undefined) {
            throw ("Pushing undefined on stack");
        }
        this.cat[this.index] = 1;
        this.stack[this.index++] = x;
    }

    this.push2 = function(x) {
        this.cat[this.index] = 2;
        this.stack[this.index++] = x;
    }

    this.top = function() {
        return this.stack[this.index - 1];
    }

    this.topcat = function() {
        return this.cat[this.index - 1];
    }
}

function Environment(parent, cls, method, methodtype, obj, args, argcats) {
    this.parent = parent;
    this.thread = CurrentThread;
    this.cls = cls;
    this.method = method;
    this.obj = obj;
    this.args = args;
    this.stack = parent ? parent.stack : new Stack();
    this.local = [];
    this.pc = 0;

    var i = 0;
    if (methodtype !== ACC_STATIC) {
        this.local[0] = obj;
        i++;
    }
    for (var a = 0; a < args.length; a++) {
        this.local[i] = args[a];
        if (argcats && argcats[a] === 2) {
            i += 2;
        } else {
            i++;
        }
    }

    this.pop = function() { return this.stack.pop(); }
    this.push1 = function(x) { this.stack.push1(x); }
    this.push2 = function(x) { this.stack.push2(x); }
    this.top = function() { return this.stack.top(); }
    this.topcat = function() { return this.stack.topcat(); }
}

function ConsolePrintStream() {
    this.println = function(s) {
        print(s);
    }
}

function startMethod(env, cls, method, methodtype, obj, args, argcats) {
    if (DEBUG_METHOD_CALLS) {
        var countdepth = function(d, e) { return e ? countdepth(d+1, e.parent) : d; }
        //print("startMethod", countdepth(0, env), cls.name, method, dump(obj), dump(args));
        var indent = "";
        for (var i = countdepth(0, env); i > 0; i--) indent += "  ";
        var aa = [];
        for (var i = 0; i < args.length; i++) {
            if (args[i] === null) {
                aa.push("null");
            } else if (args[i].__jvm_class === JString) {
                aa.push('"' + args[i].value.s + '"');
            } else {
                aa.push(args[i].toString());
            }
        }
        print(indent, "startMethod", cls.name, method, "(" + aa.join(", ") + ")");
    }

    var objcls = obj && methodtype === 0 ? obj.__jvm_class : cls;
    if (objcls === undefined) {
        throw ("objclass undefined, obj: " + dump(obj));
    }
    if (!objcls.methods[method]) {
        throw ("method " + method + " undefined");
    }
    var m = objcls.methods[method].thunk;
    if (m) {
        return m(env, cls, methodtype, obj, args, argcats);
    } else {
        throw ("Undefined method: " + method + "; obj: " + dump(obj) + " methods: " + dump(objcls.methods));
    }
}

function step(env) {
    var code = env.method.attribute_by_name["Code"].attr.code;
    var pc = env.pc;
    while (true) {
        if (DEBUG_TRACE_STACK) {
            var st = "stack: ";
            for (var i = 0; i < env.stack.index; i++) {
                st += env.stack.stack[i] + ", ";
            }
            print(st);
        }
        var op = code[pc][0];

        if (DEBUG_TRACE_DISASSEMBLE) {
            var r = "trace";
            for (var e = env; e != null; e = e.parent) {
                r += " " + e.cls.name + "." + e.method.name;
            }
            print(r);
            disassemble1(pc, code[pc]);
        }

        var next = Opcode[op](env.cls, env, code[pc], pc);
        if (next === undefined) {
            throw ("Unimplemented opcode: " + op + " " + OpcodeName[op]);
        }
        if (next instanceof Environment) {
            env.pc = pc + 1;
            env = next;
            break;
        } else if (next < 0) {
            env = env.parent;
            break;
        } else {
            pc = next;
        }
    }
    return env;
}

function runMethod(env, cls, method, methodtype, obj, args, argcats) {
    var e = startMethod(env, cls, method, methodtype, obj, args, argcats);
    while (e !== env) {
        e = step(e);
    }
}

var Classpath = ["."];
var StartClass;
var Args = [];

var a = 0;
while (a < arguments.length) {
    if (arguments[a].charAt(0) === "-") {
        switch (arguments[a]) {
            case "-cp":
                a++;
                Classpath = arguments[a].split(":");
                break;
            default:
                throw ("Unknown option: " + arguments[a]);
        }
    } else {
        StartClass = arguments[a];
        Args = arguments.slice(a+1);
        break;
    }
    a++;
}

try {
    var fcl = new FileClassLoader(Classpath);
    fcl.bootstrap();
    fcl.getClass("java/lang/String");
    var jltg = fcl.getClass("java/lang/ThreadGroup");
    var tg = jltg.newInstance();
    runMethod(null, jltg, "<init>()V", 0, tg, [], []);
    var jlt = fcl.getClass("java/lang/Thread");
    CurrentThread = jlt.newInstance();
    runMethod(null, jlt, "<init>(Ljava/lang/ThreadGroup;Ljava/lang/String;)V", 0, CurrentThread, [tg, null], [1, 1]);
    var jls = fcl.getClass("java/lang/System").newInstance();
    jls.out = new ConsolePrintStream();
    var c = fcl.getClass(StartClass);
    //c.dump();
    runMethod(null, c, "main([Ljava/lang/String;)V", ACC_STATIC, null, [], []);
} catch (e) {
    if (e.rhinoException) {
        e.rhinoException.printStackTrace();
    }
    print(e);
}
