jsenv = Environment()
jsenv.Append(JAVACLASSPATH="js.jar")
jsenv.Java(".", ["FileLoader.java"])

env = Environment()
env.Java(".", ["Opcodes.java", "OpcodeCoverage.java", "OpcodeTest.java", "Hello.java"])
env.Command(None, ["OpcodeCoverage.class", "Opcodes.class"], "java OpcodeCoverage")
env.Command(None, ["OpcodeTest.class", "Opcodes.class"], "java -ea OpcodeTest")
