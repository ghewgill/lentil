#!/bin/sh

java -cp js.jar:. org.mozilla.javascript.tools.shell.Main -debug -w lentil.js $*
