<html><head><title>Apache Tomcat/7.0.88 - Error report</title><style><!--H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}HR {color : #525D76;}--></style> </head><body><h1>HTTP Status 500 - java.lang.NullPointerException</h1><HR size="1" noshade="noshade"><p><b>type</b> Exception report</p><p><b>message</b> <u>java.lang.NullPointerException</u></p><p><b>description</b> <u>The server encountered an internal error that prevented it from fulfilling this request.</u></p><p><b>exception</b> <pre>org.apache.jasper.JasperException: java.lang.NullPointerException
	org.apache.jasper.servlet.JspServletWrapper.handleJspException(JspServletWrapper.java:561)
	org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:477)
	org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:395)
	org.apache.jasper.servlet.JspServlet.service(JspServlet.java:339)
	javax.servlet.http.HttpServlet.service(HttpServlet.java:731)
	org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)
</pre></p><p><b>root cause</b> <pre>java.lang.NullPointerException
	examples.ShowSource.doEndTag(ShowSource.java:43)
	org.apache.jsp.jsp.source_jsp._jspService(source_jsp.java:103)
	org.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:70)
	javax.servlet.http.HttpServlet.service(HttpServlet.java:731)
	org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:439)
	org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:395)
	org.apache.jasper.servlet.JspServlet.service(JspServlet.java:339)
	javax.servlet.http.HttpServlet.service(HttpServlet.java:731)
	org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)
</pre></p><p><b>note</b> <u>The full stack trace of the root cause is available in the Apache Tomcat/7.0.88 logs.</u></p><HR size="1" noshade="noshade"><h3>Apache Tomcat/7.0.88</h3></body></html>