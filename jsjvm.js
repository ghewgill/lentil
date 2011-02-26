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

function ClassError(msg) {
    this.name = "ClassError";
    this.message = msg;
}

function DataInput(bytes) {
    this.data = bytes;
    this.index = 0;

    this.readBytes = function(n) {
        var r = "";
        for (var i = 0; i < n; i++) {
            r += String.fromCharCode(this.readUnsignedByte());
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

function ConstantClass(cls, din) {
    this.cls = cls;
    this.name_index = din.readUnsignedShort();

    this.toString = function() {
        return "<class " + this.cls.constant_pool[this.name_index] + ">";
    }
}

function ConstantFieldref(cls, din) {
    this.cls = cls;
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.toString = function() {
        return "<fieldref " + this.cls.constant_pool[this.class_index] + " " + this.cls.constant_pool[this.name_and_type_index] + ">";
    }
}

function ConstantMethodref(cls, din) {
    this.cls = cls;
    this.class_index = din.readUnsignedShort();
    this.name_and_type_index = din.readUnsignedShort();

    this.toString = function() {
        return "<methodref " + this.cls.constant_pool[this.class_index] + " " + this.cls.constant_pool[this.name_and_type_index] + ">";
    }
}

function ConstantNameAndType(cls, din) {
    this.cls = cls;
    this.name_index = din.readUnsignedShort();
    this.descriptor_index = din.readUnsignedShort();

    this.toString = function() {
        return "<nameandtype " + this.cls.constant_pool[this.name_index] + " " + this.cls.constant_pool[this.descriptor_index] + ">";
    }
}

function ConstantString(cls, din) {
    this.cls = cls;
    this.string_index = din.readUnsignedShort();

    this.toString = function() {
        return "<string " + this.cls.constant_pool[this.string_index] + ">";
    }
}

function ConstantUtf8(cls, din) {
    this.length = din.readUnsignedShort();
    this.bytes = din.readBytes(this.length);

    this.toString = function() {
        return this.bytes;
    }
}

var AttributeDecoder = {
    "ConstantValue": function(cls, din) {
        print("here");
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

    var name = cls.constant_pool[this.attribute_name_index].toString();
    if (name in AttributeDecoder) {
        print(name);
        this.attr = new AttributeDecoder[name](cls, new DataInput(this.info));
    }

    this.attribute_name = cls.constant_pool[this.attribute_name_index];

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
    for (var i = 0; i < this.attributes_count; i++) {
        this.attributes[i] = new Attribute(cls, din);
    }

    this.name = cls.constant_pool[this.name_index];
    this.descriptor = cls.constant_pool[this.descriptor_index];

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

function ClassFile(bytes) {
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
                throw new ClassError("Unknown constant pool tag");
        }
        this.constant_pool[i] = cp;
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
        this.methods[i] = new MethodInfo(this, din);
    }
    this.attributes_count = din.readUnsignedShort();
    this.attributes = [];
    for (var i = 0; i < this.attributes_count; i++) {
        this.attributes[i] = new Attribute(this, din);
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
}

defineClass("FileLoader");
var f = new FileLoader(arguments[0] + ".class");
var c = new ClassFile(f.readAll());
c.dump();
