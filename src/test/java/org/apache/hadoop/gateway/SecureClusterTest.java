/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.apache.hadoop.http.HttpConfig;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.ssl.KeyStoreTestUtil;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.PropertyConfigurator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Principal;
import java.util.Properties;

import static org.apache.hadoop.hdfs.DFSConfigKeys.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class SecureClusterTest {

  static MiniDFSCluster miniDFSCluster;
  static MiniKdc kdc;
  static HdfsConfiguration configuration;
  static int nameNodeHttpPort = 50070;
  static String userName;


  @BeforeClass
  public static void setupSuite() throws Exception {
    configuration = new HdfsConfiguration();
    initKdc();
    miniDFSCluster = new MiniDFSCluster.Builder(configuration)
        .nameNodePort(20112)
        .nameNodeHttpPort(nameNodeHttpPort)
        .numDataNodes(0)
        .format(true)
        .racks(null)
        .build();
  }

  public static void initKdc() throws Exception {
    File baseDir = new File(KeyStoreTestUtil.getClasspathDir(SecureClusterTest.class));
    Properties kdcConf = MiniKdc.createConf();
    kdc = new MiniKdc(kdcConf, baseDir);
    kdc.start();

    configuration = new HdfsConfiguration();
    SecurityUtil.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.KERBEROS, configuration);
    UserGroupInformation.setConfiguration(configuration);
    assertTrue("Expected configuration to enable security", UserGroupInformation.isSecurityEnabled());
    userName = UserGroupInformation.getLoginUser().getShortUserName();
    File keytabFile = new File(baseDir, userName + ".keytab");
    String keytab = keytabFile.getAbsolutePath();
    // Windows will not reverse name lookup "127.0.0.1" to "localhost".
    String krbInstance = Path.WINDOWS ? "127.0.0.1" : "localhost";
    kdc.createPrincipal(keytabFile, userName + "/" + krbInstance, "HTTP/" + krbInstance);
    String hdfsPrincipal = userName + "/" + krbInstance + "@" + kdc.getRealm();
    String spnegoPrincipal = "HTTP/" + krbInstance + "@" + kdc.getRealm();

    configuration.set(DFS_NAMENODE_KERBEROS_PRINCIPAL_KEY, hdfsPrincipal);
    configuration.set(DFS_NAMENODE_KEYTAB_FILE_KEY, keytab);
    configuration.set(DFS_DATANODE_KERBEROS_PRINCIPAL_KEY, hdfsPrincipal);
    configuration.set(DFS_DATANODE_KEYTAB_FILE_KEY, keytab);
    configuration.set(DFS_WEB_AUTHENTICATION_KERBEROS_PRINCIPAL_KEY, spnegoPrincipal);
    configuration.set(DFS_JOURNALNODE_KEYTAB_FILE_KEY, keytab);
    configuration.set(DFS_JOURNALNODE_KERBEROS_PRINCIPAL_KEY, hdfsPrincipal);
    configuration.set(DFS_JOURNALNODE_KERBEROS_INTERNAL_SPNEGO_PRINCIPAL_KEY, spnegoPrincipal);
    configuration.setBoolean(DFS_BLOCK_ACCESS_TOKEN_ENABLE_KEY, true);
    configuration.set(DFS_DATA_ENCRYPTION_ALGORITHM_KEY, "authentication");
    configuration.set(DFS_HTTP_POLICY_KEY, HttpConfig.Policy.HTTP_AND_HTTPS.name());
    configuration.set(DFS_NAMENODE_HTTPS_ADDRESS_KEY, "localhost:0");
    configuration.set(DFS_DATANODE_HTTPS_ADDRESS_KEY, "localhost:0");
    configuration.set(DFS_JOURNALNODE_HTTPS_ADDRESS_KEY, "localhost:0");
    configuration.setInt(IPC_CLIENT_CONNECT_MAX_RETRIES_KEY, 10);

    String keystoresDir = baseDir.getAbsolutePath();
    File sslClientConfFile = new File(keystoresDir + "/ssl-client.xml");
    File sslServerConfFile = new File(keystoresDir + "/ssl-server.xml");
    KeyStoreTestUtil.setupSSLConfig(keystoresDir, keystoresDir, configuration, false);
    configuration.set(DFS_CLIENT_HTTPS_KEYSTORE_RESOURCE_KEY,
        sslClientConfFile.getName());
    configuration.set(DFS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY,
        sslServerConfFile.getName());

    //kerberos setup for http client
    File jaasConf = setupJaasConf(baseDir, keytab, hdfsPrincipal);
    System.setProperty("java.security.krb5.conf", kdc.getKrb5conf().getAbsolutePath());
    System.setProperty("java.security.auth.login.config", jaasConf.getAbsolutePath());
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
    System.setProperty("sun.security.krb5.debug", "true");

  }

  @AfterClass
  public static void cleanupSuite() throws Exception {
    kdc.stop();
    miniDFSCluster.shutdown();
  }

  @Test
  public void basicGetUserHomeRequest() throws Exception {
    setupLogging();
    CloseableHttpClient client = getHttpClient();
    String method = "GET";
    String uri = String.format("http://localhost:%s/webhdfs/v1?op=GETHOMEDIRECTORY&user.name=%s", nameNodeHttpPort, userName);
    HttpHost target = new HttpHost("localhost", nameNodeHttpPort, "http");
    System.out.println("host " + target.getAddress() + " port " + target.getPort());
    HttpRequest request = new BasicHttpRequest(method, uri);
    CloseableHttpResponse response = client.execute(target, request);
    String json = EntityUtils.toString(response.getEntity());
    response.close();

    assertEquals("{\"Path\":\"/user/" + userName + "\"}", json);
    System.out.println(json);
  }

  private CloseableHttpClient getHttpClient() {
    CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    credentialsProvider.setCredentials(AuthScope.ANY, new Credentials() {
      @Override
      public Principal getUserPrincipal() {
        return null;
      }

      @Override
      public String getPassword() {
        return null;
      }
    });

    Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
        .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true))
        .build();

    return HttpClients.custom()
        .setDefaultAuthSchemeRegistry(authSchemeRegistry)
        .setDefaultCredentialsProvider(credentialsProvider)
        .build();
  }

  private static void setupLogging() {
    PropertyConfigurator.configure(ClassLoader.getSystemResource("log4j.properties"));
  }

  private static File setupJaasConf(File baseDir, String keyTabFile, String principal) throws IOException {
    File file = new File(baseDir, "jaas.conf");
    if (!file.exists()) {
      file.createNewFile();
    } else {
      file.delete();
      file.createNewFile();
    }
    FileWriter writer = new FileWriter(file);
    String content = String.format("com.sun.security.jgss.initiate {\n" +
        "com.sun.security.auth.module.Krb5LoginModule required\n" +
        "renewTGT=true\n" +
        "doNotPrompt=true\n" +
        "useKeyTab=true\n" +
        "keyTab=\"%s\"\n" +
        "principal=\"%s\"\n" +
        "isInitiator=true\n" +
        "storeKey=true\n" +
        "useTicketCache=true\n" +
        "client=true;\n" +
        "};\n", keyTabFile, principal);
    writer.write(content);
    writer.close();
    return file;
  }

}
