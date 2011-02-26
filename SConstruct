jsenv = Environment()
jsenv.Append(JAVACLASSPATH="/Users/greg/Desktop/rhino1_6R7/js.jar")
jsenv.Java(".", ["File.java", "FileLoader.java"])

env = Environment()
env.Java(".", ["Opcodes.java", "OpcodeCoverage.java"])
env.Command(None, "Opcodes.class", "java OpcodeCoverage")
