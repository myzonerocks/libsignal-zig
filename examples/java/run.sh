#!/bin/sh
set -e

JNA_VERSION=5.14.0
JNA_JAR=lib/jna-${JNA_VERSION}.jar
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"

mkdir -p lib out

if [ ! -f "$JNA_JAR" ]; then
    echo "Downloading JNA ${JNA_VERSION}..."
    curl -fsSL "$JNA_URL" -o "$JNA_JAR"
fi

javac -cp "$JNA_JAR" -d out Main.java
java --enable-native-access=ALL-UNNAMED -cp "out:$JNA_JAR" Main
