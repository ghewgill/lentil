#!/bin/sh

java -cp ~/Desktop/rhino1_6R7/js.jar:. org.mozilla.javascript.tools.shell.Main -debug -w jsjvm.js $*
