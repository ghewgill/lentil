# Lentil

Lentil is an ECMAscript (Javascript) implementation of a java virtual machine.

## Ideas

It should be possible to use a Canvas element in a browser to offer mostly the
same functionality as a traditional java applet, without java.

Furthermore, this could be a foundation on which to build a JVM bytecode to
Javascript compiler, allowing the use of non-java languages such as Scala or
Clojure.

## Prerequisites

1. [Rhino](http://www.mozilla.org/rhino/)
2. [GNU Classpath](http://www.gnu.org/software/classpath/)
3. [SCons](http://scons.org)

## Preparation

1. Copy (or link) `js.jar` from Rhino into this directory
2. Unzip `glibj.jar` from Classpath into this directory
3. Run `scons` to build the java parts and sample programs

## Running

Use the `go` script as an easy way to launch:

    $ ./go Hello
    Hello world
