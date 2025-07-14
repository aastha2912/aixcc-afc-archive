// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;

import java.io.File;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.lang.invoke.MethodHandle;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.catalina.servlets.DefaultServlet;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.catalina.LifecycleException;

public class Http11ProcessorDefaultServletFuzzer {
    static Tomcat tomcat = null;
    static Connector connector1 = null;
    static Context ctx = null;
    static String contextPath = null;
    static String baseDir = null;

    // hook to detect path traversal vulns
    @MethodHook(
        type = HookType.BEFORE,
        targetClassName = "java.io.FileInputStream",
        targetMethod = "<init>"
    )
    public static void fileInputStreamHook(MethodHandle method, Object thisObject, Object[] arguments, int hookId) {
        if (arguments.length == 0 || contextPath == null) {
            return;
        }
        Object argObj = arguments[0];
        Path normalizedPath;
        try {
            if (argObj instanceof String) {
                normalizedPath = Paths.get((String)argObj).normalize();
            } else if (argObj instanceof File) {
                normalizedPath = Paths.get(((File)argObj).getAbsolutePath()).normalize();
            } else {
                return;
            }
        } catch (InvalidPathException e) {
            return;
        }
        if (!normalizedPath.startsWith(contextPath)) {
            Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh("Path traversal detected"));
        }
    }

    public static void fuzzerTearDown() {
        try {
            tomcat.stop();
            tomcat.destroy();
            tomcat = null;
            System.gc();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Teardown Error!");
        }
    }

    public static void fuzzerInitialize() {
        tomcat = new Tomcat();

        baseDir = "./temp";
        File index = new File(baseDir + "/index");
        try {
            Files.createDirectories(Paths.get(baseDir));
            index.createNewFile();
        } catch (IOException e) { }

        tomcat.setBaseDir(baseDir);

        connector1 = tomcat.getConnector();
        connector1.setPort(0);

        contextPath = new File("./").getAbsolutePath();

        ctx = tomcat.addContext("", contextPath);

        StandardRoot resources = new StandardRoot(ctx);
        resources.setAllowLinking(true);
        ctx.setResources(resources);

        Wrapper w = Tomcat.addServlet(ctx, "servlet", new DefaultServlet());
        ctx.addServletMappingDecoded("/", "servlet");

        try {
            tomcat.start();
        } catch (LifecycleException e) {
            throw new FuzzerSecurityIssueLow("Tomcat Start error!");
        }

    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        com.code_intelligence.jazzer.api.BugDetectors.allowNetworkConnections(
            (host, port) -> "localhost".equals(host) && port == tomcat.getConnector().getLocalPort()
        );

        SocketAddress addr = new InetSocketAddress("localhost", tomcat.getConnector().getLocalPort());
        Socket socket = new Socket();
        Writer writer;
        BufferedReader reader;
        try {
            socket.connect(addr, 0);
            socket.setSoTimeout(1000);
            OutputStream os = socket.getOutputStream();
            writer = new OutputStreamWriter(os, "US-ASCII");
            InputStream is = socket.getInputStream();
            Reader r = new InputStreamReader(is, "US-ASCII");
            reader = new BufferedReader(r);
        } catch (IOException e) {
            return;
        }

        Byte b = data.consumeByte();
        String str = data.consumeAsciiString(100);
        String str1 = data.consumeAsciiString(100);
        String str2 = data.consumeAsciiString(100);
        String str3 = data.consumeAsciiString(100);
        String str4 = data.consumeAsciiString(100);
        String str5 = data.consumeRemainingAsAsciiString();
        switch (b) {
            case 0: {
                // GET request
                try {
                    writer.write("GET http://localhost:" + tomcat.getConnector().getLocalPort() + "/temp/" + str + " HTTP/1.1\r\n");
                    writer.write("Host: localhost:" + tomcat.getConnector().getLocalPort() + "\r\n");
                    writer.write("Transfer-Encoding: chunked\r\n");
                    writer.write(str1 + "\r\n");
                    writer.write(str2 + "\r\n");
                    writer.write(str3 + "\r\n");
                    writer.write(str4 + "\r\n");
                    writer.write(str5 + "\r\n");
                    writer.write("\r\n");
                    writer.write("\r\n");
                    writer.flush();
                    reader.readLine();
                    socket.close();
                } catch (IOException e) {
                }
                break;
            }
            case 1: {
                // POST request
                try {
                    // Write the headers
                    writer.write("POST http://localhost:" + tomcat.getConnector().getLocalPort() + "/temp HTTP/1.1\r\n");
                    writer.write("Host: localhost:" + tomcat.getConnector().getLocalPort() + "\r\n");
                    writer.write("Transfer-Encoding: chunked\r\n");
                    writer.write(str + "\r\n");
                    writer.write(str1 + "\r\n");
                    writer.write(str2 + "\r\n");
                    writer.write("\r\n");
                    writer.flush();

                    // Write the request body
                    writer.write(str3 + "\r\n");
                    writer.write(str4 + "\r\n");
                    writer.write(str5 + "\r\n");
                    writer.write("\r\n");
                    writer.flush();
                    reader.readLine();
                    socket.close();
                } catch (IOException e) {
                }
                break;
            }
        }
    }
}